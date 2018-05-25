/**
 * External Apps Management Domain Models
 */

/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_auth_service/external/views.py/#lines-58
 */

export interface CreateExternalAppAuthTokenBody {
    card_author_id?: number;
    card_id: number;
    uri: string;
}

/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_auth_service/external/views.py/#lines-66
 */

export interface CreateExternalAppAuthTokenResponse {
    token: string;
}

/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_auth_service/external/views.py/#lines-30
 */

export interface ReadExternalappconfQuery {
    uri: string;
}

/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_auth_service/external/serializers.py/#lines-8
 */

export interface ReadExternalappconfResponse {
    id?: number;
    logo_uri?: string;
    source_bg_color?: string;
    source_fg_color?: string;
    target_bg_color?: string;
    target_fg_color?: string;
    uri_pattern: string;
}