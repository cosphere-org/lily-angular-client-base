/**
 * Account Settings Management Domain Models
 */

/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_auth_service/account_setting/views.py/#lines-17
 */

export interface UpdateAccountsettingBody {
    help_freq?: number;
    help_view_last_seen?: Object;
    lang?: string;
    recaller_breaker_value?: number;
    recaller_timer_value?: number;
}

/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_auth_service/account_setting/serializers.py/#lines-8
 */

export interface UpdateAccountsettingResponse {
    help_freq?: number;
    help_view_last_seen?: Object;
    lang?: string;
    recaller_breaker_value?: number;
    recaller_timer_value?: number;
}

/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_auth_service/account_setting/serializers.py/#lines-8
 */

export interface ReadAccountsettingResponse {
    help_freq?: number;
    help_view_last_seen?: Object;
    lang?: string;
    recaller_breaker_value?: number;
    recaller_timer_value?: number;
}