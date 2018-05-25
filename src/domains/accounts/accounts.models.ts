/**
 * Accounts Management Domain Models
 */

/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_auth_service/account/views/activate_account.py/#lines-91
 */

export interface ActivateAccountBody {
    code: string;
    email: string;
}

/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/.venv/src/lily/lily/base/serializers.py/#lines-158
 */

export interface ActivateAccountResponse {}

/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_auth_service/account/views/authenticate.py/#lines-15
 */

export interface AuthenticateUserBody {
    external?: boolean;
}

/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_auth_service/account/views/authenticate.py/#lines-18
 */

export interface AuthenticateUserResponse {
    account_type: string;
    app_uri?: string;
    card_author_id?: number;
    card_id?: number;
    email?: string;
    user_id: number;
}

/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_auth_service/account/views/account.py/#lines-176
 */

export interface BulkReadAccountsQuery {
    user_ids: number[];
}

/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_auth_service/account/serializers.py/#lines-23
 */

export enum BulkReadAccountsResponseAtype {
    ADMIN = 'ADMIN',
    FREE = 'FREE',
    LEARNER = 'LEARNER',
    MENTOR = 'MENTOR',
    PARTNER = 'PARTNER',
}

export interface BulkReadAccountsResponse {
    accounts: {
        atype?: BulkReadAccountsResponseAtype;
        avatar_uri?: string;
        show_in_ranking?: boolean;
        user_id?: any;
        username?: string;
    }[];
}

/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_auth_service/account/views/change_password.py/#lines-24
 */

export interface ChangePasswordBody {
    password: string;
    password_again: string;
}

/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/.venv/src/lily/lily/base/serializers.py/#lines-158
 */

export interface ChangePasswordResponse {}

/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_auth_service/account/views/account.py/#lines-112
 */

export interface CreateAccountBody {
    email: string;
    password: string;
    password_again: string;
}

/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/.venv/src/lily/lily/base/serializers.py/#lines-158
 */

export interface CreateAccountResponse {}

/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_auth_service/account/serializers.py/#lines-8
 */

export enum ReadAccountResponseAtype {
    ADMIN = 'ADMIN',
    FREE = 'FREE',
    LEARNER = 'LEARNER',
    MENTOR = 'MENTOR',
    PARTNER = 'PARTNER',
}

export interface ReadAccountResponse {
    atype?: ReadAccountResponseAtype;
    avatar_uri?: string;
    show_in_ranking?: boolean;
    user_id?: any;
    username?: string;
}

/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_auth_service/account/views/reset_password.py/#lines-94
 */

export interface ResetPasswordBody {
    code: string;
    email: string;
    password: string;
    password_again: string;
}

/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_auth_service/account/serializers.py/#lines-30
 */

export interface ResetPasswordResponse {
    token: string;
}

/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_auth_service/account/views/activate_account.py/#lines-46
 */

export interface SendAccountActivationEmailBody {
    email: string;
}

/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/.venv/src/lily/lily/base/serializers.py/#lines-158
 */

export interface SendAccountActivationEmailResponse {}

/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_auth_service/account/views/reset_password.py/#lines-31
 */

export interface SendResetPasswordEmailBody {
    email: string;
}

/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/.venv/src/lily/lily/base/serializers.py/#lines-158
 */

export interface SendResetPasswordEmailResponse {}

/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_auth_service/account/views/account.py/#lines-56
 */

export interface UpdateAccountBody {
    avatar_uri?: string;
    show_in_ranking?: boolean;
    username?: string;
}

/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_auth_service/account/serializers.py/#lines-8
 */

export enum UpdateAccountResponseAtype {
    ADMIN = 'ADMIN',
    FREE = 'FREE',
    LEARNER = 'LEARNER',
    MENTOR = 'MENTOR',
    PARTNER = 'PARTNER',
}

export interface UpdateAccountResponse {
    atype?: UpdateAccountResponseAtype;
    avatar_uri?: string;
    show_in_ranking?: boolean;
    user_id?: any;
    username?: string;
}