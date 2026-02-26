// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Admin Team & Permission Panel
 *
 * Internal no-code team role and permission management UI.
 */

import { useCallback, useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Loader2, ShieldCheck, Users } from 'lucide-react';

import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Checkbox } from '@/components/ui/checkbox';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { AdminSubscriptionAssigner } from './AdminSubscriptionAssigner';
import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from '@/components/ui/table';
import { useToast } from '@/hooks/use-toast';
import {
    type RolePermissionMatrixRow,
    type TeamMember,
    type TeamPermissionRole,
    type TeamRole,
    listRolePermissions,
    listTeamMembers,
    setRolePermission,
    setTeamMemberRole,
} from '@/services/adminService';

const ROLE_ORDER: TeamRole[] = ['user', 'moderator', 'admin'];
const PERMISSION_ROLE_ORDER: TeamPermissionRole[] = ['moderator', 'admin'];

interface AdminTeamPermissionsPanelProps {
    permissions: string[];
}

/**
 * Renders team-role and role-permission management for internal staff.
 *
 * @param props - Component props
 * @returns Team/permission admin panel
 */
export function AdminTeamPermissionsPanel({ permissions }: AdminTeamPermissionsPanelProps) {
    const { t } = useTranslation();
    const { toast } = useToast();

    const canReadRoles = permissions.includes('team.roles.read');
    const canManageRoles = permissions.includes('team.roles.manage');
    const canReadPermissions = permissions.includes('team.permissions.read');
    const canManagePermissions = permissions.includes('team.permissions.manage');
    const canManageSubscriptions = permissions.includes('subscriptions.manage');

    const [members, setMembers] = useState<TeamMember[]>([]);
    const [permissionRows, setPermissionRows] = useState<RolePermissionMatrixRow[]>([]);

    const [isLoadingMembers, setIsLoadingMembers] = useState(false);
    const [isLoadingPermissions, setIsLoadingPermissions] = useState(false);
    const [updatingMemberId, setUpdatingMemberId] = useState<string | null>(null);
    const [updatingPermissionKey, setUpdatingPermissionKey] = useState<string | null>(null);

    const groupedPermissionRows = useMemo(() => {
        const grouped = new Map<string, RolePermissionMatrixRow[]>();
        for (const row of permissionRows) {
            const category = row.category || 'other';
            const current = grouped.get(category) || [];
            current.push(row);
            grouped.set(category, current);
        }
        return Array.from(grouped.entries());
    }, [permissionRows]);

    const loadMembers = useCallback(async () => {
        if (!canReadRoles) {
            setMembers([]);
            return;
        }

        setIsLoadingMembers(true);
        const { members: rows, error } = await listTeamMembers();
        setIsLoadingMembers(false);

        if (error) {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('admin.team.membersLoadError'),
            });
            return;
        }

        setMembers(rows);
    }, [canReadRoles, t, toast]);

    const loadPermissions = useCallback(async () => {
        if (!canReadPermissions) {
            setPermissionRows([]);
            return;
        }

        setIsLoadingPermissions(true);
        const { permissions: rows, error } = await listRolePermissions();
        setIsLoadingPermissions(false);

        if (error) {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('admin.team.permissionsLoadError'),
            });
            return;
        }

        setPermissionRows(rows);
    }, [canReadPermissions, t, toast]);

    useEffect(() => {
        void loadMembers();
    }, [loadMembers]);

    useEffect(() => {
        void loadPermissions();
    }, [loadPermissions]);

    const handleRoleChange = async (userId: string, role: TeamRole) => {
        if (!canManageRoles) {
            return;
        }

        setUpdatingMemberId(userId);
        const { error } = await setTeamMemberRole(userId, role);
        setUpdatingMemberId(null);

        if (error) {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('admin.team.roleUpdateError'),
            });
            return;
        }

        setMembers((current) =>
            current.map((member) => {
                if (member.user_id !== userId) {
                    return member;
                }

                const roles: TeamRole[] = role === 'user' ? ['user'] : ['user', role];
                return {
                    ...member,
                    primary_role: role,
                    roles,
                };
            }),
        );

        toast({
            title: t('common.success'),
            description: t('admin.team.roleUpdated'),
        });
    };

    const handlePermissionToggle = async (
        permissionKey: string,
        role: TeamPermissionRole,
        enabled: boolean,
    ) => {
        if (!canManagePermissions) {
            return;
        }

        const updateKey = `${permissionKey}:${role}`;
        setUpdatingPermissionKey(updateKey);
        const { error } = await setRolePermission(role, permissionKey, enabled);
        setUpdatingPermissionKey(null);

        if (error) {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('admin.team.permissionsUpdateError'),
            });
            return;
        }

        setPermissionRows((current) =>
            current.map((row) => {
                if (row.permission_key !== permissionKey) {
                    return row;
                }
                return {
                    ...row,
                    roles: {
                        ...row.roles,
                        [role]: enabled,
                    },
                };
            }),
        );

        toast({
            title: t('common.success'),
            description: t('admin.team.permissionsUpdated'),
        });
    };

    const hasAnyAccess = canReadRoles || canReadPermissions || canManageSubscriptions;

    if (!hasAnyAccess) {
        return (
            <Card>
                <CardHeader>
                    <CardTitle>{t('admin.team.title')}</CardTitle>
                    <CardDescription>{t('admin.team.noAccess')}</CardDescription>
                </CardHeader>
            </Card>
        );
    }

    return (
        <div className="space-y-4">
            {canReadRoles && (
                <Card>
                    <CardHeader>
                        <CardTitle className="flex items-center gap-2 text-base">
                            <Users className="w-4 h-4" />
                            {t('admin.team.membersTitle')}
                        </CardTitle>
                        <CardDescription>{t('admin.team.membersDescription')}</CardDescription>
                    </CardHeader>
                    <CardContent>
                        {isLoadingMembers ? (
                            <div className="flex items-center gap-2 text-sm text-muted-foreground">
                                <Loader2 className="w-4 h-4 animate-spin" />
                                {t('common.loading')}
                            </div>
                        ) : members.length === 0 ? (
                            <p className="text-sm text-muted-foreground">{t('admin.team.noMembers')}</p>
                        ) : (
                            <Table>
                                <TableHeader>
                                    <TableRow>
                                        <TableHead>{t('admin.team.columns.member')}</TableHead>
                                        <TableHead>{t('admin.team.columns.roles')}</TableHead>
                                        <TableHead>{t('admin.team.columns.primaryRole')}</TableHead>
                                    </TableRow>
                                </TableHeader>
                                <TableBody>
                                    {members.map((member) => (
                                        <TableRow key={member.user_id}>
                                            <TableCell>
                                                <div className="space-y-0.5">
                                                    <p className="font-medium text-sm">
                                                        {member.email || member.user_id}
                                                    </p>
                                                    {member.display_name && (
                                                        <p className="text-xs text-muted-foreground">
                                                            {member.display_name}
                                                        </p>
                                                    )}
                                                </div>
                                            </TableCell>
                                            <TableCell>
                                                <div className="flex flex-wrap gap-1">
                                                    {member.roles.map((role) => (
                                                        <Badge key={`${member.user_id}-${role}`} variant="outline">
                                                            {t(`admin.team.roleLabels.${role}`)}
                                                        </Badge>
                                                    ))}
                                                </div>
                                            </TableCell>
                                            <TableCell>
                                                <Select
                                                    value={member.primary_role}
                                                    onValueChange={(value) =>
                                                        void handleRoleChange(member.user_id, value as TeamRole)
                                                    }
                                                    disabled={!canManageRoles || updatingMemberId === member.user_id}
                                                >
                                                    <SelectTrigger className="w-[180px]">
                                                        <SelectValue />
                                                    </SelectTrigger>
                                                    <SelectContent>
                                                        {ROLE_ORDER.map((role) => (
                                                            <SelectItem key={`${member.user_id}-${role}`} value={role}>
                                                                {t(`admin.team.roleLabels.${role}`)}
                                                            </SelectItem>
                                                        ))}
                                                    </SelectContent>
                                                </Select>
                                            </TableCell>
                                        </TableRow>
                                    ))}
                                </TableBody>
                            </Table>
                        )}
                    </CardContent>
                </Card>
            )}

            {canReadPermissions && (
                <Card>
                    <CardHeader>
                        <CardTitle className="flex items-center gap-2 text-base">
                            <ShieldCheck className="w-4 h-4" />
                            {t('admin.team.permissionsTitle')}
                        </CardTitle>
                        <CardDescription>{t('admin.team.permissionsDescription')}</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-4">
                        {isLoadingPermissions ? (
                            <div className="flex items-center gap-2 text-sm text-muted-foreground">
                                <Loader2 className="w-4 h-4 animate-spin" />
                                {t('common.loading')}
                            </div>
                        ) : permissionRows.length === 0 ? (
                            <p className="text-sm text-muted-foreground">{t('admin.team.noPermissions')}</p>
                        ) : (
                            groupedPermissionRows.map(([category, rows]) => (
                                <div key={category} className="space-y-2">
                                    <h4 className="text-sm font-semibold uppercase tracking-wide text-muted-foreground">
                                        {t(`admin.team.categories.${category}`, {
                                            defaultValue: category,
                                        })}
                                    </h4>
                                    <Table>
                                        <TableHeader>
                                            <TableRow>
                                                <TableHead>{t('admin.team.permissionColumns.permission')}</TableHead>
                                                <TableHead>{t('admin.team.permissionColumns.moderator')}</TableHead>
                                                <TableHead>{t('admin.team.permissionColumns.admin')}</TableHead>
                                            </TableRow>
                                        </TableHeader>
                                        <TableBody>
                                            {rows.map((row) => (
                                                <TableRow key={row.permission_key}>
                                                    <TableCell>
                                                        <div className="space-y-0.5">
                                                            <p className="font-medium text-sm">{row.label}</p>
                                                            <p className="text-xs text-muted-foreground">
                                                                {row.description}
                                                            </p>
                                                            <p className="text-[11px] text-muted-foreground">
                                                                {row.permission_key}
                                                            </p>
                                                        </div>
                                                    </TableCell>
                                                    {PERMISSION_ROLE_ORDER.map((role) => {
                                                        const isBusy = updatingPermissionKey === `${row.permission_key}:${role}`;
                                                        return (
                                                            <TableCell key={`${row.permission_key}-${role}`}>
                                                                <div className="flex items-center gap-2">
                                                                    <Checkbox
                                                                        checked={row.roles[role]}
                                                                        disabled={!canManagePermissions || isBusy}
                                                                        onCheckedChange={(checked) =>
                                                                            void handlePermissionToggle(
                                                                                row.permission_key,
                                                                                role,
                                                                                Boolean(checked),
                                                                            )
                                                                        }
                                                                    />
                                                                    {isBusy && (
                                                                        <Loader2 className="w-3.5 h-3.5 animate-spin text-muted-foreground" />
                                                                    )}
                                                                </div>
                                                            </TableCell>
                                                        );
                                                    })}
                                                </TableRow>
                                            ))}
                                        </TableBody>
                                    </Table>
                                </div>
                            ))
                        )}
                    </CardContent>
                </Card>
            )}

            {canManageSubscriptions && (
                <Card>
                    <CardHeader>
                        <CardTitle>
                            {t('admin.team.subscriptionTitle')}
                        </CardTitle>
                    </CardHeader>
                    <CardContent>
                        <AdminSubscriptionAssigner />
                    </CardContent>
                </Card>
            )}
        </div>
    );
}
