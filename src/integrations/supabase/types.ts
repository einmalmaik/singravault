export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[]

export type Database = {
  // Allows to automatically instantiate createClient with right options
  // instead of createClient<Database, { PostgrestVersion: 'XX' }>(URL, KEY)
  __InternalSupabase: {
    PostgrestVersion: "14.1"
  }
  public: {
    Tables: {
      backup_codes: {
        Row: {
          code_hash: string
          created_at: string | null
          id: string
          is_used: boolean | null
          used_at: string | null
          user_id: string
        }
        Insert: {
          code_hash: string
          created_at?: string | null
          id?: string
          is_used?: boolean | null
          used_at?: string | null
          user_id: string
        }
        Update: {
          code_hash?: string
          created_at?: string | null
          id?: string
          is_used?: boolean | null
          used_at?: string | null
          user_id?: string
        }
        Relationships: []
      }
      categories: {
        Row: {
          color: string | null
          created_at: string
          icon: string | null
          id: string
          name: string
          parent_id: string | null
          sort_order: number | null
          updated_at: string
          user_id: string
        }
        Insert: {
          color?: string | null
          created_at?: string
          icon?: string | null
          id?: string
          name: string
          parent_id?: string | null
          sort_order?: number | null
          updated_at?: string
          user_id: string
        }
        Update: {
          color?: string | null
          created_at?: string
          icon?: string | null
          id?: string
          name?: string
          parent_id?: string | null
          sort_order?: number | null
          updated_at?: string
          user_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "categories_parent_id_fkey"
            columns: ["parent_id"]
            isOneToOne: false
            referencedRelation: "categories"
            referencedColumns: ["id"]
          },
        ]
      }
      collection_audit_log: {
        Row: {
          action: string
          collection_id: string
          created_at: string
          details: Json | null
          id: string
          user_id: string | null
        }
        Insert: {
          action: string
          collection_id: string
          created_at?: string
          details?: Json | null
          id?: string
          user_id?: string | null
        }
        Update: {
          action?: string
          collection_id?: string
          created_at?: string
          details?: Json | null
          id?: string
          user_id?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "collection_audit_log_collection_id_fkey"
            columns: ["collection_id"]
            isOneToOne: false
            referencedRelation: "shared_collections"
            referencedColumns: ["id"]
          },
        ]
      }
      collection_keys: {
        Row: {
          collection_id: string
          created_at: string
          id: string
          pq_wrapped_key: string | null
          user_id: string
          wrapped_key: string
        }
        Insert: {
          collection_id: string
          created_at?: string
          id?: string
          pq_wrapped_key?: string | null
          user_id: string
          wrapped_key: string
        }
        Update: {
          collection_id?: string
          created_at?: string
          id?: string
          pq_wrapped_key?: string | null
          user_id?: string
          wrapped_key?: string
        }
        Relationships: [
          {
            foreignKeyName: "collection_keys_collection_id_fkey"
            columns: ["collection_id"]
            isOneToOne: false
            referencedRelation: "shared_collections"
            referencedColumns: ["id"]
          },
        ]
      }
      emergency_access: {
        Row: {
          created_at: string
          encrypted_master_key: string | null
          granted_at: string | null
          grantor_id: string
          id: string
          pq_encrypted_master_key: string | null
          requested_at: string | null
          status: string
          trusted_email: string
          trusted_user_id: string | null
          trustee_pq_public_key: string | null
          trustee_public_key: string | null
          updated_at: string
          wait_days: number
        }
        Insert: {
          created_at?: string
          encrypted_master_key?: string | null
          granted_at?: string | null
          grantor_id: string
          id?: string
          pq_encrypted_master_key?: string | null
          requested_at?: string | null
          status?: string
          trusted_email: string
          trusted_user_id?: string | null
          trustee_pq_public_key?: string | null
          trustee_public_key?: string | null
          updated_at?: string
          wait_days?: number
        }
        Update: {
          created_at?: string
          encrypted_master_key?: string | null
          granted_at?: string | null
          grantor_id?: string
          id?: string
          pq_encrypted_master_key?: string | null
          requested_at?: string | null
          status?: string
          trusted_email?: string
          trusted_user_id?: string | null
          trustee_pq_public_key?: string | null
          trustee_public_key?: string | null
          updated_at?: string
          wait_days?: number
        }
        Relationships: []
      }
      family_members: {
        Row: {
          family_owner_id: string
          id: string
          invited_at: string
          joined_at: string | null
          member_email: string
          member_user_id: string | null
          role: string
          status: string
        }
        Insert: {
          family_owner_id: string
          id?: string
          invited_at?: string
          joined_at?: string | null
          member_email: string
          member_user_id?: string | null
          role?: string
          status?: string
        }
        Update: {
          family_owner_id?: string
          id?: string
          invited_at?: string
          joined_at?: string | null
          member_email?: string
          member_user_id?: string | null
          role?: string
          status?: string
        }
        Relationships: []
      }
      file_attachments: {
        Row: {
          created_at: string
          encrypted: boolean | null
          encrypted_metadata: string | null
          file_name: string
          file_size: number
          id: string
          mime_type: string | null
          storage_path: string
          updated_at: string
          user_id: string
          vault_item_id: string
        }
        Insert: {
          created_at?: string
          encrypted?: boolean | null
          encrypted_metadata?: string | null
          file_name: string
          file_size: number
          id?: string
          mime_type?: string | null
          storage_path: string
          updated_at?: string
          user_id: string
          vault_item_id: string
        }
        Update: {
          created_at?: string
          encrypted?: boolean | null
          encrypted_metadata?: string | null
          file_name?: string
          file_size?: number
          id?: string
          mime_type?: string | null
          storage_path?: string
          updated_at?: string
          user_id?: string
          vault_item_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "file_attachments_vault_item_id_fkey"
            columns: ["vault_item_id"]
            isOneToOne: false
            referencedRelation: "vault_items"
            referencedColumns: ["id"]
          },
        ]
      }
      opaque_login_states: {
        Row: {
          created_at: string
          expires_at: string
          id: string
          opaque_identifier: string | null
          server_login_state: string
          user_id: string
        }
        Insert: {
          created_at?: string
          expires_at: string
          id?: string
          opaque_identifier?: string | null
          server_login_state: string
          user_id: string
        }
        Update: {
          created_at?: string
          expires_at?: string
          id?: string
          opaque_identifier?: string | null
          server_login_state?: string
          user_id?: string
        }
        Relationships: []
      }
      opaque_password_reset_states: {
        Row: {
          consumed_at: string | null
          created_at: string
          email: string
          expires_at: string
          id: string
          user_id: string
        }
        Insert: {
          consumed_at?: string | null
          created_at?: string
          email: string
          expires_at: string
          id?: string
          user_id: string
        }
        Update: {
          consumed_at?: string | null
          created_at?: string
          email?: string
          expires_at?: string
          id?: string
          user_id?: string
        }
        Relationships: []
      }
      opaque_registration_challenges: {
        Row: {
          consumed_at: string | null
          created_at: string
          email: string
          expires_at: string
          id: string
          purpose: string
          user_id: string | null
        }
        Insert: {
          consumed_at?: string | null
          created_at?: string
          email: string
          expires_at: string
          id?: string
          purpose: string
          user_id?: string | null
        }
        Update: {
          consumed_at?: string | null
          created_at?: string
          email?: string
          expires_at?: string
          id?: string
          purpose?: string
          user_id?: string | null
        }
        Relationships: []
      }
      opaque_reenrollment_required: {
        Row: {
          detected_at: string
          email: string
          reason: string
          user_id: string
        }
        Insert: {
          detected_at?: string
          email: string
          reason?: string
          user_id: string
        }
        Update: {
          detected_at?: string
          email?: string
          reason?: string
          user_id?: string
        }
        Relationships: []
      }
      passkey_credentials: {
        Row: {
          aaguid: string | null
          counter: number
          created_at: string
          credential_id: string
          device_name: string
          id: string
          last_used_at: string | null
          prf_enabled: boolean
          prf_salt: string | null
          public_key: string
          rp_id: string | null
          transports: string[] | null
          user_id: string
          wrapped_master_key: string | null
        }
        Insert: {
          aaguid?: string | null
          counter?: number
          created_at?: string
          credential_id: string
          device_name?: string
          id?: string
          last_used_at?: string | null
          prf_enabled?: boolean
          prf_salt?: string | null
          public_key: string
          rp_id?: string | null
          transports?: string[] | null
          user_id: string
          wrapped_master_key?: string | null
        }
        Update: {
          aaguid?: string | null
          counter?: number
          created_at?: string
          credential_id?: string
          device_name?: string
          id?: string
          last_used_at?: string | null
          prf_enabled?: boolean
          prf_salt?: string | null
          public_key?: string
          rp_id?: string | null
          transports?: string[] | null
          user_id?: string
          wrapped_master_key?: string | null
        }
        Relationships: []
      }
      profiles: {
        Row: {
          auth_protocol: string
          avatar_url: string | null
          created_at: string
          display_name: string | null
          duress_kdf_version: number | null
          duress_password_verifier: string | null
          duress_salt: string | null
          encryption_salt: string | null
          encrypted_user_key: string | null
          hide_community_ads: boolean | null
          id: string
          kdf_version: number
          legacy_crypto_disabled_at: string | null
          master_password_verifier: string | null
          pq_encrypted_private_key: string | null
          pq_enforced_at: string | null
          pq_key_version: number | null
          pq_public_key: string | null
          preferred_language: string | null
          security_standard_version: number | null
          theme: string | null
          updated_at: string
          user_id: string
        }
        Insert: {
          auth_protocol?: string
          avatar_url?: string | null
          created_at?: string
          display_name?: string | null
          duress_kdf_version?: number | null
          duress_password_verifier?: string | null
          duress_salt?: string | null
          encryption_salt?: string | null
          encrypted_user_key?: string | null
          hide_community_ads?: boolean | null
          id?: string
          kdf_version?: number
          legacy_crypto_disabled_at?: string | null
          master_password_verifier?: string | null
          pq_encrypted_private_key?: string | null
          pq_enforced_at?: string | null
          pq_key_version?: number | null
          pq_public_key?: string | null
          preferred_language?: string | null
          security_standard_version?: number | null
          theme?: string | null
          updated_at?: string
          user_id: string
        }
        Update: {
          auth_protocol?: string
          avatar_url?: string | null
          created_at?: string
          display_name?: string | null
          duress_kdf_version?: number | null
          duress_password_verifier?: string | null
          duress_salt?: string | null
          encryption_salt?: string | null
          encrypted_user_key?: string | null
          hide_community_ads?: boolean | null
          id?: string
          kdf_version?: number
          legacy_crypto_disabled_at?: string | null
          master_password_verifier?: string | null
          pq_encrypted_private_key?: string | null
          pq_enforced_at?: string | null
          pq_key_version?: number | null
          pq_public_key?: string | null
          preferred_language?: string | null
          security_standard_version?: number | null
          theme?: string | null
          updated_at?: string
          user_id?: string
        }
        Relationships: []
      }
      rate_limit_attempts: {
        Row: {
          action: string
          attempted_at: string
          created_at: string
          id: string
          identifier: string
          ip_address: string | null
          locked_until: string | null
          success: boolean
          user_agent: string | null
        }
        Insert: {
          action: string
          attempted_at?: string
          created_at?: string
          id?: string
          identifier: string
          ip_address?: string | null
          locked_until?: string | null
          success?: boolean
          user_agent?: string | null
        }
        Update: {
          action?: string
          attempted_at?: string
          created_at?: string
          id?: string
          identifier?: string
          ip_address?: string | null
          locked_until?: string | null
          success?: boolean
          user_agent?: string | null
        }
        Relationships: []
      }
      recovery_tokens: {
        Row: {
          created_at: string | null
          email: string
          expires_at: string
          id: string
          purpose: string
          token_hash: string
          used_at: string | null
        }
        Insert: {
          created_at?: string | null
          email: string
          expires_at: string
          id?: string
          purpose?: string
          token_hash: string
          used_at?: string | null
        }
        Update: {
          created_at?: string | null
          email?: string
          expires_at?: string
          id?: string
          purpose?: string
          token_hash?: string
          used_at?: string | null
        }
        Relationships: []
      }
      password_reset_challenges: {
        Row: {
          authorized_at: string | null
          email: string
          email_verified_at: string | null
          expires_at: string
          id: string
          ip_address: string | null
          issued_at: string
          purpose: string
          token_hash: string
          two_factor_required: boolean
          two_factor_verified_at: string | null
          used_at: string | null
          user_agent: string | null
          user_id: string
        }
        Insert: {
          authorized_at?: string | null
          email: string
          email_verified_at?: string | null
          expires_at: string
          id?: string
          ip_address?: string | null
          issued_at?: string
          purpose?: string
          token_hash: string
          two_factor_required?: boolean
          two_factor_verified_at?: string | null
          used_at?: string | null
          user_agent?: string | null
          user_id: string
        }
        Update: {
          authorized_at?: string | null
          email?: string
          email_verified_at?: string | null
          expires_at?: string
          id?: string
          ip_address?: string | null
          issued_at?: string
          purpose?: string
          token_hash?: string
          two_factor_required?: boolean
          two_factor_verified_at?: string | null
          used_at?: string | null
          user_agent?: string | null
          user_id?: string
        }
        Relationships: []
      }
      role_permissions: {
        Row: {
          created_at: string
          id: string
          permission_key: string
          role: Database["public"]["Enums"]["app_role"]
        }
        Insert: {
          created_at?: string
          id?: string
          permission_key: string
          role: Database["public"]["Enums"]["app_role"]
        }
        Update: {
          created_at?: string
          id?: string
          permission_key?: string
          role?: Database["public"]["Enums"]["app_role"]
        }
        Relationships: [
          {
            foreignKeyName: "role_permissions_permission_key_fkey"
            columns: ["permission_key"]
            isOneToOne: false
            referencedRelation: "team_permissions"
            referencedColumns: ["permission_key"]
          },
        ]
      }
      shared_collection_items: {
        Row: {
          added_by: string | null
          collection_id: string
          created_at: string
          encrypted_data: string | null
          id: string
          vault_item_id: string
        }
        Insert: {
          added_by?: string | null
          collection_id: string
          created_at?: string
          encrypted_data?: string | null
          id?: string
          vault_item_id: string
        }
        Update: {
          added_by?: string | null
          collection_id?: string
          created_at?: string
          encrypted_data?: string | null
          id?: string
          vault_item_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "shared_collection_items_collection_id_fkey"
            columns: ["collection_id"]
            isOneToOne: false
            referencedRelation: "shared_collections"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "shared_collection_items_vault_item_id_fkey"
            columns: ["vault_item_id"]
            isOneToOne: false
            referencedRelation: "vault_items"
            referencedColumns: ["id"]
          },
        ]
      }
      shared_collection_members: {
        Row: {
          collection_id: string
          created_at: string
          id: string
          permission: string
          user_id: string
        }
        Insert: {
          collection_id: string
          created_at?: string
          id?: string
          permission?: string
          user_id: string
        }
        Update: {
          collection_id?: string
          created_at?: string
          id?: string
          permission?: string
          user_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "shared_collection_members_collection_id_fkey"
            columns: ["collection_id"]
            isOneToOne: false
            referencedRelation: "shared_collections"
            referencedColumns: ["id"]
          },
        ]
      }
      shared_collections: {
        Row: {
          created_at: string
          description: string | null
          id: string
          item_count: number | null
          member_count: number | null
          name: string
          owner_id: string
          updated_at: string
        }
        Insert: {
          created_at?: string
          description?: string | null
          id?: string
          item_count?: number | null
          member_count?: number | null
          name: string
          owner_id: string
          updated_at?: string
        }
        Update: {
          created_at?: string
          description?: string | null
          id?: string
          item_count?: number | null
          member_count?: number | null
          name?: string
          owner_id?: string
          updated_at?: string
        }
        Relationships: []
      }
      subscriptions: {
        Row: {
          cancel_at_period_end: boolean | null
          created_at: string | null
          current_period_end: string | null
          has_used_intro_discount: boolean | null
          id: string
          status: string | null
          stripe_customer_id: string | null
          stripe_price_id: string | null
          stripe_subscription_id: string | null
          tier: string | null
          updated_at: string | null
          user_id: string
        }
        Insert: {
          cancel_at_period_end?: boolean | null
          created_at?: string | null
          current_period_end?: string | null
          has_used_intro_discount?: boolean | null
          id?: string
          status?: string | null
          stripe_customer_id?: string | null
          stripe_price_id?: string | null
          stripe_subscription_id?: string | null
          tier?: string | null
          updated_at?: string | null
          user_id: string
        }
        Update: {
          cancel_at_period_end?: boolean | null
          created_at?: string | null
          current_period_end?: string | null
          has_used_intro_discount?: boolean | null
          id?: string
          status?: string | null
          stripe_customer_id?: string | null
          stripe_price_id?: string | null
          stripe_subscription_id?: string | null
          tier?: string | null
          updated_at?: string | null
          user_id?: string
        }
        Relationships: []
      }
      support_events: {
        Row: {
          actor_user_id: string | null
          created_at: string
          event_payload: Json | null
          event_type: string
          id: string
          ticket_id: string
        }
        Insert: {
          actor_user_id?: string | null
          created_at?: string
          event_payload?: Json | null
          event_type: string
          id?: string
          ticket_id: string
        }
        Update: {
          actor_user_id?: string | null
          created_at?: string
          event_payload?: Json | null
          event_type?: string
          id?: string
          ticket_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "support_events_ticket_id_fkey"
            columns: ["ticket_id"]
            isOneToOne: false
            referencedRelation: "support_tickets"
            referencedColumns: ["id"]
          },
        ]
      }
      support_messages: {
        Row: {
          author_role: string
          author_user_id: string | null
          body: string
          created_at: string
          id: string
          is_internal: boolean
          ticket_id: string
        }
        Insert: {
          author_role: string
          author_user_id?: string | null
          body: string
          created_at?: string
          id?: string
          is_internal?: boolean
          ticket_id: string
        }
        Update: {
          author_role?: string
          author_user_id?: string | null
          body?: string
          created_at?: string
          id?: string
          is_internal?: boolean
          ticket_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "support_messages_ticket_id_fkey"
            columns: ["ticket_id"]
            isOneToOne: false
            referencedRelation: "support_tickets"
            referencedColumns: ["id"]
          },
        ]
      }
      support_tickets: {
        Row: {
          category: string
          closed_at: string | null
          created_at: string
          first_responded_by: string | null
          first_response_at: string | null
          first_response_minutes: number | null
          id: string
          is_priority: boolean
          last_message_at: string
          priority_reason: string
          requester_email: string | null
          resolved_at: string | null
          sla_due_at: string
          sla_hours: number
          status: string
          subject: string
          tier_snapshot: string
          updated_at: string
          user_id: string
        }
        Insert: {
          category?: string
          closed_at?: string | null
          created_at?: string
          first_responded_by?: string | null
          first_response_at?: string | null
          first_response_minutes?: number | null
          id?: string
          is_priority?: boolean
          last_message_at?: string
          priority_reason?: string
          requester_email?: string | null
          resolved_at?: string | null
          sla_due_at?: string
          sla_hours?: number
          status?: string
          subject: string
          tier_snapshot?: string
          updated_at?: string
          user_id: string
        }
        Update: {
          category?: string
          closed_at?: string | null
          created_at?: string
          first_responded_by?: string | null
          first_response_at?: string | null
          first_response_minutes?: number | null
          id?: string
          is_priority?: boolean
          last_message_at?: string
          priority_reason?: string
          requester_email?: string | null
          resolved_at?: string | null
          sla_due_at?: string
          sla_hours?: number
          status?: string
          subject?: string
          tier_snapshot?: string
          updated_at?: string
          user_id?: string
        }
        Relationships: []
      }
      tags: {
        Row: {
          color: string | null
          created_at: string
          id: string
          name: string
          user_id: string
        }
        Insert: {
          color?: string | null
          created_at?: string
          id?: string
          name: string
          user_id: string
        }
        Update: {
          color?: string | null
          created_at?: string
          id?: string
          name?: string
          user_id?: string
        }
        Relationships: []
      }
      team_access_audit_log: {
        Row: {
          action: string
          actor_user_id: string | null
          created_at: string
          id: string
          payload: Json | null
          target_user_id: string | null
        }
        Insert: {
          action: string
          actor_user_id?: string | null
          created_at?: string
          id?: string
          payload?: Json | null
          target_user_id?: string | null
        }
        Update: {
          action?: string
          actor_user_id?: string | null
          created_at?: string
          id?: string
          payload?: Json | null
          target_user_id?: string | null
        }
        Relationships: []
      }
      team_permissions: {
        Row: {
          category: string
          created_at: string
          description: string
          label: string
          permission_key: string
        }
        Insert: {
          category: string
          created_at?: string
          description: string
          label: string
          permission_key: string
        }
        Update: {
          category?: string
          created_at?: string
          description?: string
          label?: string
          permission_key?: string
        }
        Relationships: []
      }
      user_2fa: {
        Row: {
          created_at: string | null
          enabled_at: string | null
          id: string
          is_enabled: boolean | null
          last_verified_at: string | null
          totp_secret: string | null
          totp_secret_enc: string | null
          updated_at: string | null
          user_id: string
          vault_2fa_enabled: boolean | null
        }
        Insert: {
          created_at?: string | null
          enabled_at?: string | null
          id?: string
          is_enabled?: boolean | null
          last_verified_at?: string | null
          totp_secret?: string | null
          totp_secret_enc?: string | null
          updated_at?: string | null
          user_id: string
          vault_2fa_enabled?: boolean | null
        }
        Update: {
          created_at?: string | null
          enabled_at?: string | null
          id?: string
          is_enabled?: boolean | null
          last_verified_at?: string | null
          totp_secret?: string | null
          totp_secret_enc?: string | null
          updated_at?: string | null
          user_id?: string
          vault_2fa_enabled?: boolean | null
        }
        Relationships: []
      }
      user_keys: {
        Row: {
          created_at: string
          encrypted_private_key: string
          public_key: string
          updated_at: string
          user_id: string
        }
        Insert: {
          created_at?: string
          encrypted_private_key: string
          public_key: string
          updated_at?: string
          user_id: string
        }
        Update: {
          created_at?: string
          encrypted_private_key?: string
          public_key?: string
          updated_at?: string
          user_id?: string
        }
        Relationships: []
      }
      user_opaque_records: {
        Row: {
          created_at: string
          id: string
          opaque_identifier: string | null
          registration_record: string
          updated_at: string
          user_id: string
        }
        Insert: {
          created_at?: string
          id?: string
          opaque_identifier?: string | null
          registration_record: string
          updated_at?: string
          user_id: string
        }
        Update: {
          created_at?: string
          id?: string
          opaque_identifier?: string | null
          registration_record?: string
          updated_at?: string
          user_id?: string
        }
        Relationships: []
      }
      user_roles: {
        Row: {
          created_at: string
          id: string
          role: Database["public"]["Enums"]["app_role"]
          user_id: string
        }
        Insert: {
          created_at?: string
          id?: string
          role?: Database["public"]["Enums"]["app_role"]
          user_id: string
        }
        Update: {
          created_at?: string
          id?: string
          role?: Database["public"]["Enums"]["app_role"]
          user_id?: string
        }
        Relationships: []
      }
      user_security: {
        Row: {
          argon2_hash: string
          created_at: string | null
          id: string
          updated_at: string | null
        }
        Insert: {
          argon2_hash: string
          created_at?: string | null
          id: string
          updated_at?: string | null
        }
        Update: {
          argon2_hash?: string
          created_at?: string | null
          id?: string
          updated_at?: string | null
        }
        Relationships: []
      }
      vault_item_tags: {
        Row: {
          created_at: string
          id: string
          tag_id: string
          vault_item_id: string
        }
        Insert: {
          created_at?: string
          id?: string
          tag_id: string
          vault_item_id: string
        }
        Update: {
          created_at?: string
          id?: string
          tag_id?: string
          vault_item_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "vault_item_tags_tag_id_fkey"
            columns: ["tag_id"]
            isOneToOne: false
            referencedRelation: "tags"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "vault_item_tags_vault_item_id_fkey"
            columns: ["vault_item_id"]
            isOneToOne: false
            referencedRelation: "vault_items"
            referencedColumns: ["id"]
          },
        ]
      }
      vault_items: {
        Row: {
          category_id: string | null
          created_at: string
          encrypted_data: string
          icon_url: string | null
          id: string
          is_favorite: boolean | null
          item_type: Database["public"]["Enums"]["vault_item_type"]
          last_used_at: string | null
          sort_order: number | null
          title: string
          updated_at: string
          user_id: string
          vault_id: string
          website_url: string | null
        }
        Insert: {
          category_id?: string | null
          created_at?: string
          encrypted_data: string
          icon_url?: string | null
          id?: string
          is_favorite?: boolean | null
          item_type?: Database["public"]["Enums"]["vault_item_type"]
          last_used_at?: string | null
          sort_order?: number | null
          title?: string
          updated_at?: string
          user_id: string
          vault_id: string
          website_url?: string | null
        }
        Update: {
          category_id?: string | null
          created_at?: string
          encrypted_data?: string
          icon_url?: string | null
          id?: string
          is_favorite?: boolean | null
          item_type?: Database["public"]["Enums"]["vault_item_type"]
          last_used_at?: string | null
          sort_order?: number | null
          title?: string
          updated_at?: string
          user_id?: string
          vault_id?: string
          website_url?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "vault_items_category_id_fkey"
            columns: ["category_id"]
            isOneToOne: false
            referencedRelation: "categories"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "vault_items_vault_id_fkey"
            columns: ["vault_id"]
            isOneToOne: false
            referencedRelation: "vaults"
            referencedColumns: ["id"]
          },
        ]
      }
      vaults: {
        Row: {
          created_at: string
          description: string | null
          id: string
          is_default: boolean | null
          name: string
          updated_at: string
          user_id: string
        }
        Insert: {
          created_at?: string
          description?: string | null
          id?: string
          is_default?: boolean | null
          name?: string
          updated_at?: string
          user_id: string
        }
        Update: {
          created_at?: string
          description?: string | null
          id?: string
          is_default?: boolean | null
          name?: string
          updated_at?: string
          user_id?: string
        }
        Relationships: []
      }
      sensitive_action_challenges: {
        Row: {
          action: string
          expires_at: string
          id: string
          issued_at: string
          user_id: string
        }
        Insert: {
          action: string
          expires_at: string
          id?: string
          issued_at?: string
          user_id: string
        }
        Update: {
          action?: string
          expires_at?: string
          id?: string
          issued_at?: string
          user_id?: string
        }
        Relationships: []
      }
      two_factor_challenges: {
        Row: {
          consumed_at: string | null
          created_at: string
          expires_at: string
          id: string
          metadata: Json
          method: string | null
          purpose: string
          user_id: string
          verified_at: string | null
        }
        Insert: {
          consumed_at?: string | null
          created_at?: string
          expires_at: string
          id?: string
          metadata?: Json
          method?: string | null
          purpose: string
          user_id: string
          verified_at?: string | null
        }
        Update: {
          consumed_at?: string | null
          created_at?: string
          expires_at?: string
          id?: string
          metadata?: Json
          method?: string | null
          purpose?: string
          user_id?: string
          verified_at?: string | null
        }
        Relationships: []
      }
      webauthn_challenges: {
        Row: {
          challenge: string
          created_at: string
          expires_at: string
          id: string
          type: string
          user_id: string
        }
        Insert: {
          challenge: string
          created_at?: string
          expires_at?: string
          id?: string
          type: string
          user_id: string
        }
        Update: {
          challenge?: string
          created_at?: string
          expires_at?: string
          id?: string
          type?: string
          user_id?: string
        }
        Relationships: []
      }
    }
    Views: {
      [_ in never]: never
    }
    Functions: {
      auto_close_stale_support_tickets: { Args: never; Returns: number }
      begin_vault_reset_recovery: { Args: never; Returns: Json }
      check_family_size: { Args: { owner_id: string }; Returns: number }
      check_subscription_tier: { Args: { user_id: string }; Returns: string }
      cleanup_expired_opaque_login_states: { Args: never; Returns: undefined }
      cleanup_expired_webauthn_challenges: { Args: never; Returns: undefined }
      cleanup_old_rate_limit_attempts: { Args: never; Returns: undefined }
      delete_my_account: {
        Args: { p_two_factor_challenge_id?: string | null }
        Returns: Json
      }
      get_my_permissions: {
        Args: never
        Returns: {
          permission_key: string
        }[]
      }
      get_support_response_metrics: {
        Args: { _days?: number }
        Returns: {
          avg_first_response_hours: number
          avg_first_response_minutes: number
          responded_count: number
          segment: string
          sla_hit_rate_percent: number
          ticket_count: number
          window_days: number
        }[]
      }
      get_support_sla_for_user: {
        Args: { _user_id: string }
        Returns: {
          is_priority: boolean
          priority_reason: string
          sla_hours: number
          tier_snapshot: string
        }[]
      }
      get_totp_encryption_key: { Args: never; Returns: string }
      get_user_2fa_secret: {
        Args: { p_require_enabled?: boolean; p_user_id: string }
        Returns: string
      }
      get_user_id_by_email: {
        Args: { p_email: string }
        Returns: {
          email: string
          id: string
        }[]
      }
      has_permission: {
        Args: { _permission_key: string; _user_id: string }
        Returns: boolean
      }
      has_role: {
        Args: {
          _role: Database["public"]["Enums"]["app_role"]
          _user_id: string
        }
        Returns: boolean
      }
      initialize_user_2fa_secret: {
        Args: { p_secret: string; p_user_id: string }
        Returns: undefined
      }
      is_shared_collection_member: {
        Args: { _collection_id: string; _user_id: string }
        Returns: boolean
      }
      rotate_collection_key_atomic: {
        Args: { p_collection_id: string; p_items: Json; p_new_keys: Json }
        Returns: undefined
      }
      reset_user_vault_state: {
        Args: { p_recovery_challenge_id: string }
        Returns: Json
      }
      rotate_totp_encryption_key: {
        Args: { p_new_key: string }
        Returns: number
      }
      user_2fa_decrypt_secret: {
        Args: { _secret_enc: string }
        Returns: string
      }
      user_2fa_encrypt_secret: { Args: { _secret: string }; Returns: string }
      user_has_active_paid_subscription: {
        Args: { p_user_id: string }
        Returns: boolean
      }
    }
    Enums: {
      app_role: "admin" | "moderator" | "user"
      vault_item_type: "password" | "note" | "totp"
    }
    CompositeTypes: {
      [_ in never]: never
    }
  }
}

type DatabaseWithoutInternals = Omit<Database, "__InternalSupabase">

type DefaultSchema = DatabaseWithoutInternals[Extract<keyof Database, "public">]

export type Tables<
  DefaultSchemaTableNameOrOptions extends
    | keyof (DefaultSchema["Tables"] & DefaultSchema["Views"])
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
        DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
      DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])[TableName] extends {
      Row: infer R
    }
    ? R
    : never
  : DefaultSchemaTableNameOrOptions extends keyof (DefaultSchema["Tables"] &
        DefaultSchema["Views"])
    ? (DefaultSchema["Tables"] &
        DefaultSchema["Views"])[DefaultSchemaTableNameOrOptions] extends {
        Row: infer R
      }
      ? R
      : never
    : never

export type TablesInsert<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Insert: infer I
    }
    ? I
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Insert: infer I
      }
      ? I
      : never
    : never

export type TablesUpdate<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Update: infer U
    }
    ? U
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Update: infer U
      }
      ? U
      : never
    : never

export type Enums<
  DefaultSchemaEnumNameOrOptions extends
    | keyof DefaultSchema["Enums"]
    | { schema: keyof DatabaseWithoutInternals },
  EnumName extends DefaultSchemaEnumNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"]
    : never = never,
> = DefaultSchemaEnumNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"][EnumName]
  : DefaultSchemaEnumNameOrOptions extends keyof DefaultSchema["Enums"]
    ? DefaultSchema["Enums"][DefaultSchemaEnumNameOrOptions]
    : never

export type CompositeTypes<
  PublicCompositeTypeNameOrOptions extends
    | keyof DefaultSchema["CompositeTypes"]
    | { schema: keyof DatabaseWithoutInternals },
  CompositeTypeName extends PublicCompositeTypeNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"]
    : never = never,
> = PublicCompositeTypeNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"][CompositeTypeName]
  : PublicCompositeTypeNameOrOptions extends keyof DefaultSchema["CompositeTypes"]
    ? DefaultSchema["CompositeTypes"][PublicCompositeTypeNameOrOptions]
    : never

export const Constants = {
  public: {
    Enums: {
      app_role: ["admin", "moderator", "user"],
      vault_item_type: ["password", "note", "totp"],
    },
  },
} as const
