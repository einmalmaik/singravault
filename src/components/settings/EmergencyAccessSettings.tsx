// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Emergency Access Settings
 * 
 * Manages trusted contacts (Trustees) and access grantors.
 * Implements the Zero-Knowledge Emergency Access flow:
 * 1. Invite Trustee (User ID / Email)
 * 2. Trustee Accepts -> Generates RSA Key Pair -> Stores Private Key Encrypted in Vault
 * 3. Trustee Sends Public Key -> Grantor Encrypts Master Key with Public Key
 * 4. Access Request / Approval Flow
 */

import { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import {
    Shield,
    UserPlus,
    Clock,
    Check,
    X,
    AlertTriangle,
    Key,
    Lock,
    Unlock,
    Loader2,
    Trash2,
    Eye
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';

import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
    DialogTrigger,
} from '@/components/ui/dialog';
import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from '@/components/ui/table';
import {
    Tabs,
    TabsContent,
    TabsList,
    TabsTrigger,
} from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from '@/components/ui/select';
import { FeatureGate } from '@/components/Subscription/FeatureGate';
import { useToast } from '@/hooks/use-toast';
import { useAuth } from '@/contexts/AuthContext';
import { useVault } from '@/contexts/VaultContext';
import {
    EmergencyAccess,
    emergencyAccessService
} from '@/services/emergencyAccessService';
import {
    generateRSAKeyPair,
    exportPublicKey,
    exportPrivateKey,
    deriveRawKey
} from '@/services/cryptoService';
import { generatePQKeyPair } from '@/services/pqCryptoService';
import {
    upsertOfflineItemRow,
    enqueueOfflineMutation,
    buildVaultItemRowFromInsert,
    resolveDefaultVaultId
} from '@/services/offlineVaultService';
import { ensureHybridKeyMaterial } from '@/services/keyMaterialService';
import { isEdgeFunctionServiceError } from '@/services/edgeFunctionService';
import { supabase } from '@/integrations/supabase/client';

interface EmergencyAccessSettingsProps {
    bypassFeatureGate?: boolean;
}

export default function EmergencyAccessSettings({ bypassFeatureGate = false }: EmergencyAccessSettingsProps) {
    const { t } = useTranslation();
    const { toast } = useToast();
    const { user } = useAuth();
    const navigate = useNavigate();
    const {
        isLocked,
        encryptItem,
        decryptItem
    } = useVault();

    const [trustees, setTrustees] = useState<EmergencyAccess[]>([]);
    const [grantors, setGrantors] = useState<EmergencyAccess[]>([]);
    const [loading, setLoading] = useState(true);
    const [inviteDialogOpen, setInviteDialogOpen] = useState(false);
    const [inviteEmail, setInviteEmail] = useState('');
    const [inviteWaitDays, setInviteWaitDays] = useState('7');
    const [setupInternalOpen, setSetupInternalOpen] = useState(false);
    const [selectedGrantorId, setSelectedGrantorId] = useState<string | null>(null);
    const [masterPassword, setMasterPassword] = useState('');
    const [setupLoading, setSetupLoading] = useState(false);

    const resolveErrorMessage = (error: unknown, fallbackMessage: string) => {
        if (isEdgeFunctionServiceError(error)) {
            if (error.status === 401) {
                return t('common.authRequired');
            }

            if (error.status === 403) {
                return t('common.forbidden');
            }

            if (error.status && error.status >= 500) {
                return t('common.serviceUnavailable');
            }
        }

        return error instanceof Error ? error.message : fallbackMessage;
    };

    useEffect(() => {
        if (user && !isLocked) {
            fetchData();
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [user, isLocked]);

    const fetchData = async () => {
        setLoading(true);
        try {
            const [trusteesData, grantorsData] = await Promise.all([
                emergencyAccessService.getTrustees(),
                emergencyAccessService.getGrantors()
            ]);
            setTrustees(trusteesData);
            setGrantors(grantorsData);
        } catch (error) {
            console.error('Failed to fetch emergency access data:', error);
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('emergency.fetchError', 'Failed to load emergency access data.')
            });
        } finally {
            setLoading(false);
        }
    };

    const handleAccessVault = async (accessRecord: EmergencyAccess) => {
        if (!accessRecord.pq_encrypted_master_key) {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('emergency.noKey', 'No hybrid emergency key found. Setup not complete.')
            });
            return;
        }

        try {
            setLoading(true); // Reuse loading state or create a new one

            // 1. Find the private key in my vault
            // We search for an item where customFields.emergency_access_id matches accessRecord.id
            // Since we can't search inside encrypted_data easily without decrypting all items (expensive),
            // we rely on the implementation where we add a clear-text searchable attribute or just decrypt all notes?
            // Wait, offlineVaultService stores items. Querying by custom fields isn't directly supported by Supabase RLS unless we promoted it.
            // But we stored it in 'customFields' inside 'encrypted_data'.
            // WE MUST DECRYPT ALL NOTES TO FIND IT. This is the only way in Zero-Knowledge unless we added a tag.
            // Let's iterate over all notes in the vault. 'loadVaultSnapshot' gives us all items.

            const { data: { user: currentUser } } = await supabase.auth.getUser();
            if (!currentUser) throw new Error('No user');

            // Fetch all items (using existing service to handle offline/online)
            // Ideally we should use a hook or context method to "findItem", but context doesn't expose all items.
            // We'll fetch raw items and decrypt.
            const { data: vaultItems, error } = await supabase
                .from('vault_items')
                .select('*')
                .eq('item_type', 'note') // Only notes
                .eq('user_id', currentUser.id);

            if (error) throw error;

            let foundPrivateKeyJwk = null;
            let foundPqSecretKey: string | null = null;

            for (const item of vaultItems) {
                try {
                    const decrypted = await decryptItem(item.encrypted_data, item.id);
                    if (decrypted.customFields && decrypted.customFields.emergency_access_id === accessRecord.id) {
                        if (decrypted.customFields.private_key_jwk) {
                            foundPrivateKeyJwk = JSON.parse(decrypted.customFields.private_key_jwk);
                            foundPqSecretKey = decrypted.customFields.pq_secret_key || null;
                            break;
                        }
                    }
                } catch {
                    // Ignore decryption errors for other items
                }
            }

            if (!foundPrivateKeyJwk) {
                throw new Error('Private key not found in your vault. Did you delete the emergency access note?');
            }

            // 2. Decrypt the Grantor's Master Key
            if (!accessRecord.pq_encrypted_master_key || !foundPqSecretKey) {
                throw new Error('Security Standard v1 requires hybrid key material for emergency access.');
            }

            const rawMasterKeyJson = await emergencyAccessService.decryptHybridMasterKey(
                accessRecord.pq_encrypted_master_key,
                foundPqSecretKey,
                JSON.stringify(foundPrivateKeyJwk)
            );

            // 3. Navigate to Grantor Vault View
            // Pass the raw key and grantor details
            navigate(`/vault/emergency/${accessRecord.id}`, {
                state: {
                    masterKey: JSON.parse(rawMasterKeyJson), // Array of bytes
                    grantorName: accessRecord.grantor?.display_name || 'Grantor',
                    grantorId: accessRecord.grantor_id
                }
            });

        } catch (error) {
            console.error('Failed to access vault:', error);
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: error instanceof Error ? error.message : t('emergency.accessError', 'Failed to decrypt vault access.')
            });
        } finally {
            setLoading(false);
        }
    };

    const handleInviteTrustee = async () => {
        if (!inviteEmail) return;

        try {
            await emergencyAccessService.inviteTrustee(inviteEmail, parseInt(inviteWaitDays));
            toast({
                title: t('common.success'),
                description: t('emergency.inviteSent')
            });
            setInviteDialogOpen(false);
            setInviteEmail('');
            fetchData();
        } catch (error) {
            console.error('Failed to invite trustee:', error);
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: resolveErrorMessage(error, t('emergency.inviteError'))
            });
        }
    };

    const handleRevokeAccess = async (id: string) => {
        if (!confirm(t('common.confirmAction'))) return;

        try {
            await emergencyAccessService.revokeAccess(id);
            toast({
                title: t('common.success'),
                description: t('emergency.accessRevoked', 'Access revoked.')
            });
            fetchData();
        } catch (error) {
            console.error('Failed to revoke access:', error);
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('common.errorOccurred')
            });
        }
    };

    const handleAcceptInvite = async (invite: EmergencyAccess) => {
        if (!user) return;

        try {
            // 1. Generate RSA Key Pair
            const keyPair = await generateRSAKeyPair();
            const pqKeys = generatePQKeyPair();

            // 2. Export Public Key
            const publicKeyJwk = await exportPublicKey(keyPair.publicKey);

            // 3. Export Private Key
            const privateKeyJwk = await exportPrivateKey(keyPair.privateKey);

            // 4. Encrypt Private Key payload using VaultContext
            const privateKeyString = JSON.stringify(privateKeyJwk);

            // Create a vault item to store this key
            const itemTitle = `Emergency Key: ${invite.grantor?.display_name || 'User'}`;

            // We store the key in customFields or notes.
            // Using VaultItemData structure derived from cryptoService
            const itemData: Record<string, unknown> = {
                title: itemTitle,
                itemType: 'note',
                notes: `Emergency Access Key for access ID: ${invite.id}. \n\nDO NOT DELETE THIS ITEM manually unless you want to revoke your ability to access their vault.`,
                isFavorite: false,
                customFields: {
                    emergency_access_id: invite.id,
                    private_key_jwk: privateKeyString,
                    pq_secret_key: pqKeys.secretKey
                }
            };

            const newItemId = crypto.randomUUID();
            const encryptedBlob = await encryptItem(itemData, newItemId);

            // 5. Save generated item to Offline Vault (IndexedDB + Queue)
            const rowInsert = {
                id: newItemId,
                user_id: user.id,
                vault_id: await resolveDefaultVaultId(user.id), // Helper to get default vault
                title: itemTitle,
                encrypted_data: encryptedBlob,
                item_type: 'note',
                is_favorite: false,
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString()
            };

            // @ts-expect-error - Types compatibility issues between generated types and manual usage
            await upsertOfflineItemRow(user.id, buildVaultItemRowFromInsert(rowInsert));

            await enqueueOfflineMutation({
                userId: user.id,
                type: 'upsert_item',
                payload: rowInsert
            });

            // 6. Send hybrid public keys to server and accept invite
            await emergencyAccessService.acceptInviteWithPQ(
                invite.id,
                JSON.stringify(publicKeyJwk),
                pqKeys.publicKey
            );

            const { error: profileUpdateError } = await supabase
                .from('profiles')
                .update({
                    pq_public_key: pqKeys.publicKey,
                    pq_key_version: 1,
                    pq_enforced_at: new Date().toISOString(),
                    security_standard_version: 1,
                    legacy_crypto_disabled_at: new Date().toISOString(),
                } as Record<string, unknown>)
                .eq('user_id', user.id);

            if (profileUpdateError) {
                throw profileUpdateError;
            }

            toast({
                title: t('common.success'),
                description: t('emergency.inviteAccepted', 'Invitation accepted. Key pair generated and stored.')
            });
            fetchData();

        } catch (error) {
            console.error('Failed to accept invite:', error);
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('emergency.acceptError', 'Failed to accept invitation.')
            });
        }
    };

    const handleSetupAccess = (grantorId: string) => {
        setSelectedGrantorId(grantorId);
        setSetupInternalOpen(true);
    };

    const submitSetupAccess = async () => {
        if (!selectedGrantorId || !masterPassword) return;
        setSetupLoading(true);

        try {
            // 1. Get the trustee's public key
            const accessRecord = trustees.find(t => t.id === selectedGrantorId); // Wait, selectedGrantorId is actually access ID? No, logic below uses it as Access ID mostly.
            // The button call was: handleSetupAccess(trustee.id). 'trustee' in map is the EmergencyAccess record.

            if (!accessRecord?.trustee_public_key || !accessRecord.trustee_pq_public_key) {
                throw new Error('Security Standard v1 requires trustee PQ + RSA public keys.');
            }

            // 2. Derive the RAW master key bytes (re-derivation required as it's not kept in memory)
            // We need the salt. Where is it? In user profile or locally?
            // AuthContext or VaultContext should have it.
            // VaultContext uses 'salt' state.
            // But we need to pass it here.

            // For now, we assume we can get it from storage or context.
            // Ideally deriveKey should handle retrieving salt if not provided, but it usually needs it.
            // We can fetch user profile to get the salt.
            const { data: { user: currentUser } } = await supabase.auth.getUser();
            if (!currentUser) throw new Error('No user');

            await ensureHybridKeyMaterial({
                userId: currentUser.id,
                masterPassword,
            });

            // Fetch profile for salt and KDF version
            const { data: profile } = await supabase
                .from('profiles')
                .select('encryption_salt, kdf_version')
                .eq('user_id', currentUser.id)
                .single()
                ;

            if (!profile?.encryption_salt) throw new Error('Salt not found');
            const kdfVersion = (profile.kdf_version as number) || 1;

            // 3. Derive raw key
            const rawKeyBytes = await deriveRawKey(masterPassword, profile.encryption_salt, kdfVersion);
            try {
                const rawKeyString = JSON.stringify(Array.from(rawKeyBytes)); // Serialize bytes for encryption

                // 4. Encrypt and store using hybrid scheme (mandatory in Security Standard v1)
                await emergencyAccessService.setHybridEncryptedMasterKey(
                    accessRecord.id,
                    rawKeyString,
                    accessRecord.trustee_pq_public_key,
                    accessRecord.trustee_public_key
                );
            } finally {
                rawKeyBytes.fill(0);
            }

            toast({
                title: t('common.success'),
                description: t('emergency.setupSuccess', 'Emergency access configured.')
            });
            setSetupInternalOpen(false);
            setMasterPassword('');
            fetchData();
        } catch (error) {
            console.error('Failed to setup access:', error);
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('emergency.setupError', 'Failed to configure access. Check your password.')
            });
        } finally {
            setSetupLoading(false);
        }
    };

    const getStatusBadge = (status: string) => {
        switch (status) {
            case 'granted':
                return <Badge className="bg-green-500 hover:bg-green-600">Active</Badge>;
            case 'pending':
                return <Badge variant="outline" className="text-yellow-500 border-yellow-500">Pending</Badge>;
            case 'accepted':
                return <Badge variant="secondary">Setup Required</Badge>;
            case 'invited':
                return <Badge variant="outline">Invited</Badge>;
            case 'rejected':
                return <Badge variant="destructive">Rejected</Badge>;
            default:
                return <Badge variant="outline">{status}</Badge>;
        }
    };

    const content = (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <div>
                    <h2 className="text-lg font-medium">{t('emergency.title', 'Emergency Access')}</h2>
                    <p className="text-sm text-muted-foreground">
                        {t('emergency.description', 'Manage who can access your vault in case of emergency.')}
                    </p>
                </div>
                <Button onClick={() => setInviteDialogOpen(true)}>
                    <UserPlus className="w-4 h-4 mr-2" />
                    {t('emergency.invite', 'Invite Trustee')}
                </Button>
            </div>

            <Tabs defaultValue="trustees">
                <TabsList>
                    <TabsTrigger value="trustees">{t('emergency.tabs.trustees', 'My Trusted Contacts')}</TabsTrigger>
                    <TabsTrigger value="grantors">{t('emergency.tabs.grantors', 'Who Trusts Me')}</TabsTrigger>
                </TabsList>

                {/* TRUSTEES TAB (People I trust) */}
                <TabsContent value="trustees" className="mt-4">
                    {loading ? (
                        <div className="flex justify-center p-8"><Loader2 className="animate-spin" /></div>
                    ) : (
                        <div className="rounded-md border">
                            <Table>
                                <TableHeader>
                                    <TableRow>
                                        <TableHead>Email</TableHead>
                                        <TableHead>Status</TableHead>
                                        <TableHead>Wait Time</TableHead>
                                        <TableHead className="text-right">Actions</TableHead>
                                    </TableRow>
                                </TableHeader>
                                <TableBody>
                                    {trustees.length === 0 && (
                                        <TableRow>
                                            <TableCell colSpan={4} className="text-center py-8 text-muted-foreground">
                                                {t('emergency.noTrustees', 'No trusted contacts yet.')}
                                            </TableCell>
                                        </TableRow>
                                    )}
                                    {trustees.map((item) => (
                                        <TableRow key={item.id}>
                                            <TableCell>{item.trusted_email}</TableCell>
                                            <TableCell>{getStatusBadge(item.status)}</TableCell>
                                            <TableCell>{item.wait_days} {t('common.days', 'days')}</TableCell>
                                            <TableCell className="text-right">
                                                {item.status === 'accepted' && !item.pq_encrypted_master_key && (
                                                    <Button size="sm" onClick={() => handleSetupAccess(item.id)}>
                                                        <Key className="w-4 h-4 mr-2" />
                                                        {t('emergency.setup', 'Setup Access')}
                                                    </Button>
                                                )}
                                                <Button
                                                    variant="ghost"
                                                    size="icon"
                                                    className="text-destructive hover:text-destructive hover:bg-destructive/10"
                                                    onClick={() => handleRevokeAccess(item.id)}
                                                >
                                                    <Trash2 className="w-4 h-4" />
                                                </Button>
                                            </TableCell>
                                        </TableRow>
                                    ))}
                                </TableBody>
                            </Table>
                        </div>
                    )}
                </TabsContent>

                {/* GRANTORS TAB (People who trust me) */}
                <TabsContent value="grantors" className="mt-4">
                    {loading ? (
                        <div className="flex justify-center p-8"><Loader2 className="animate-spin" /></div>
                    ) : (
                        <div className="rounded-md border">
                            <Table>
                                <TableHeader>
                                    <TableRow>
                                        <TableHead>Grantor</TableHead>
                                        <TableHead>Status</TableHead>
                                        <TableHead>Wait Time</TableHead>
                                        <TableHead className="text-right">Actions</TableHead>
                                    </TableRow>
                                </TableHeader>
                                <TableBody>
                                    {grantors.length === 0 && (
                                        <TableRow>
                                            <TableCell colSpan={4} className="text-center py-8 text-muted-foreground">
                                                {t('emergency.noGrantors', 'You are not a trusted contact for anyone.')}
                                            </TableCell>
                                        </TableRow>
                                    )}
                                    {grantors.map((item) => (
                                        <TableRow key={item.id}>
                                            <TableCell>
                                                <div className="flex flex-col">
                                                    <span>{item.grantor?.display_name || 'Unknown'}</span>
                                                </div>
                                            </TableCell>
                                            <TableCell>{getStatusBadge(item.status)}</TableCell>
                                            <TableCell>{item.wait_days} {t('common.days', 'days')}</TableCell>
                                            <TableCell className="text-right space-x-2">
                                                {item.status === 'invited' && (
                                                    <Button size="sm" onClick={() => handleAcceptInvite(item)} disabled={loading}>
                                                        {t('common.accept', 'Accept')}
                                                    </Button>
                                                )}
                                                {/* Logic for Requesting Access */}
                                                {item.status === 'accepted' && item.pq_encrypted_master_key && (
                                                    <Button size="sm" variant="secondary" onClick={() => emergencyAccessService.requestAccess(item.id).then(fetchData)}>
                                                        {t('emergency.requestAccess', 'Request Access')}
                                                    </Button>
                                                )}
                                                {/* Logic for Accessing Vault (Granted) */}
                                                {item.status === 'granted' && item.pq_encrypted_master_key && (
                                                    <Button size="sm" onClick={() => handleAccessVault(item)}>
                                                        <Unlock className="w-4 h-4 mr-2" />
                                                        {t('emergency.accessVault', 'Access Vault')}
                                                    </Button>
                                                )}
                                                {item.status === 'pending' && (
                                                    <span className="text-xs text-muted-foreground flex items-center justify-end">
                                                        <Clock className="w-3 h-3 mr-1" /> {t('emergency.pending', 'Pending')}
                                                    </span>
                                                )}
                                            </TableCell>
                                        </TableRow>
                                    ))}
                                </TableBody>
                            </Table>
                        </div>
                    )}
                </TabsContent>
            </Tabs>

            {/* Invite Dialog */}
            <Dialog open={inviteDialogOpen} onOpenChange={setInviteDialogOpen}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>{t('emergency.inviteTitle', 'Invite Trusted Contact')}</DialogTitle>
                        <DialogDescription>
                            {t('emergency.inviteDesc', 'Enter the email address of the person you want to trust with emergency access to your vault.')}
                        </DialogDescription>
                    </DialogHeader>
                    <div className="grid gap-4 py-4">
                        <div className="grid gap-2">
                            <label htmlFor="email">{t('common.email', 'Email')}</label>
                            <Input
                                id="email"
                                value={inviteEmail}
                                onChange={(e) => setInviteEmail(e.target.value)}
                                placeholder="trustee@example.com"
                            />
                        </div>
                        <div className="grid gap-2">
                            <label htmlFor="waitDays">{t('emergency.waitTime', 'Wait Time (Days)')}</label>
                            <Select value={inviteWaitDays} onValueChange={setInviteWaitDays}>
                                <SelectTrigger>
                                    <SelectValue placeholder="Select days" />
                                </SelectTrigger>
                                <SelectContent>
                                    <SelectItem value="0">0 {t('common.days', 'days')} (Immediate)</SelectItem>
                                    <SelectItem value="1">1 {t('common.day', 'day')}</SelectItem>
                                    <SelectItem value="3">3 {t('common.days', 'days')}</SelectItem>
                                    <SelectItem value="7">7 {t('common.days', 'days')}</SelectItem>
                                    <SelectItem value="14">14 {t('common.days', 'days')}</SelectItem>
                                    <SelectItem value="30">30 {t('common.days', 'days')}</SelectItem>
                                </SelectContent>
                            </Select>
                            <p className="text-xs text-muted-foreground">
                                {t('emergency.waitTimeDetail', 'How long after they request access before they are granted entry. You can reject the request during this time.')}
                            </p>
                        </div>
                    </div>
                    <DialogFooter>
                        <Button variant="outline" onClick={() => setInviteDialogOpen(false)}>{t('common.cancel', 'Cancel')}</Button>
                        <Button onClick={handleInviteTrustee}>{t('emergency.sendInvite', 'Send Invitation')}</Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>

            {/* Setup Access Dialog (Enter Master Password) */}
            <Dialog open={setupInternalOpen} onOpenChange={setSetupInternalOpen}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>{t('emergency.confirmSetup', 'Confirm Emergency Access Setup')}</DialogTitle>
                        <DialogDescription>
                            {t('emergency.confirmSetupDesc', 'Please enter your Master Password to encrypt your vault key for this contact. They will NOT receive access immediately; they will only hold a locked key that opens after the wait period.')}
                        </DialogDescription>
                    </DialogHeader>
                    <div className="space-y-4 py-4">
                        <div className="space-y-2">
                            <label>{t('auth.masterPassword.password', 'Master Password')}</label>
                            <Input
                                type="password"
                                value={masterPassword}
                                onChange={(e) => setMasterPassword(e.target.value)}
                            />
                        </div>
                    </div>
                    <DialogFooter>
                        <Button variant="outline" onClick={() => setSetupInternalOpen(false)}>{t('common.cancel')}</Button>
                        <Button disabled={setupLoading} onClick={submitSetupAccess}>
                            {setupLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : t('common.confirm', 'Confirm')}
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>
        </div>
    );

    if (bypassFeatureGate) {
        return content;
    }

    return (
        <FeatureGate
            feature="emergency_access"
            featureLabel={t('subscription.features.emergency_access')}
        >
            {content}
        </FeatureGate>
    );
}
