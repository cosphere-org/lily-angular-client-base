/**
 * Internal Management Domain Models
 */

/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_auth_service/internal/views.py/#lines-26
 */

export enum UpdateAccountTypeAsAdminBodyAccountType {
    ADMIN = 'ADMIN',
    FREE = 'FREE',
    LEARNER = 'LEARNER',
    MENTOR = 'MENTOR',
    PARTNER = 'PARTNER',
}

export interface UpdateAccountTypeAsAdminBody {
    account_type: UpdateAccountTypeAsAdminBodyAccountType;
    user_id: number;
}

/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/.venv/src/lily/lily/base/serializers.py/#lines-158
 */

export interface UpdateAccountTypeAsAdminResponse {}