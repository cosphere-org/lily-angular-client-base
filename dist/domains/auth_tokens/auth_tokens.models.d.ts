/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
/**
 * Auth Tokens Management Domain Models
 */
/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/69bb55b04713846fc3aa1a1c300a8a9ed207b2d3/.venv/src/lily/lily/base/serializers.py/#lines-158
 */
export interface AuthorizeAuthTokenResponse {
}
/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/69bb55b04713846fc3aa1a1c300a8a9ed207b2d3/cosphere_auth_service/account/views/auth_token.py/#lines-26
 */
export interface CreateAuthTokenBody {
    email: string;
    password: string;
}
/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/69bb55b04713846fc3aa1a1c300a8a9ed207b2d3/cosphere_auth_service/account/serializers.py/#lines-30
 */
export interface CreateAuthTokenResponse {
    token: string;
}
/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/69bb55b04713846fc3aa1a1c300a8a9ed207b2d3/cosphere_auth_service/account/views/facebook.py/#lines-22
 */
export interface CreateFacebookBasedAuthTokenBody {
    code: string;
}
/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/69bb55b04713846fc3aa1a1c300a8a9ed207b2d3/cosphere_auth_service/account/serializers.py/#lines-30
 */
export interface CreateFacebookBasedAuthTokenResponse {
    token: string;
}
/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/69bb55b04713846fc3aa1a1c300a8a9ed207b2d3/cosphere_auth_service/account/views/facebook.py/#lines-22
 */
export interface CreateFacebookBasedMobileAuthTokenBody {
    access_token: string;
    email: string;
}
/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/69bb55b04713846fc3aa1a1c300a8a9ed207b2d3/cosphere_auth_service/account/serializers.py/#lines-30
 */
export interface CreateFacebookBasedMobileAuthTokenResponse {
    token: string;
}
/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/69bb55b04713846fc3aa1a1c300a8a9ed207b2d3/cosphere_auth_service/account/views/google.py/#lines-22
 */
export interface CreateGoogleBasedAuthTokenBody {
    code: string;
}
/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/69bb55b04713846fc3aa1a1c300a8a9ed207b2d3/cosphere_auth_service/account/serializers.py/#lines-30
 */
export interface CreateGoogleBasedAuthTokenResponse {
    token: string;
}
/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/69bb55b04713846fc3aa1a1c300a8a9ed207b2d3/cosphere_auth_service/account/views/google.py/#lines-22
 */
export interface CreateGoogleBasedMobileAuthTokenBody {
    access_token: string;
    email: string;
}
/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/69bb55b04713846fc3aa1a1c300a8a9ed207b2d3/cosphere_auth_service/account/serializers.py/#lines-30
 */
export interface CreateGoogleBasedMobileAuthTokenResponse {
    token: string;
}
/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/69bb55b04713846fc3aa1a1c300a8a9ed207b2d3/cosphere_auth_service/account/serializers.py/#lines-30
 */
export interface UpdateAuthTokenResponse {
    token: string;
}
