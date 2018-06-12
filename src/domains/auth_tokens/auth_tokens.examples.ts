/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */

/**
 * Auth Tokens Management Domain Examples
 */

/**
 * Examples for AUTHORIZE_AUTH_TOKEN
 */
export const AuthorizeAuthTokenExamples = {
    "200 (AUTH_TOKEN_AUTHORIZED)": {
        "content": {
            "@event": "AUTH_TOKEN_AUTHORIZED",
            "@type": "empty"
        },
        "content_type": "application/json",
        "status": 200
    },
    
    "401 (AUTH_TOKEN_WAS_BROKEN)": {
        "content": {
            "@event": "AUTH_TOKEN_WAS_BROKEN",
            "@type": "error",
            "user_id": "anonymous"
        },
        "content_type": "application/json",
        "status": 401
    }
}

/**
 * Examples for CREATE_AUTH_TOKEN
 */
export const CreateAuthTokenExamples = {
    "201 (AUTH_TOKEN_CREATED)": {
        "content": {
            "@event": "AUTH_TOKEN_CREATED",
            "@type": "auth_token",
            "token": "super.new.token.123"
        },
        "content_type": "application/json",
        "status": 201
    },
    
    "400 (BODY_DID_NOT_VALIDATE)": {
        "content": {
            "@event": "BODY_DID_NOT_VALIDATE",
            "@type": "error",
            "errors": {
                "password": [
                    "This field may not be blank."
                ]
            },
            "user_id": "anonymous"
        },
        "content_type": "application/json",
        "status": 400
    },
    
    "400 (INVALID_AUTH_TOKEN_DATA_DETECTED)": {
        "content": {
            "@event": "INVALID_AUTH_TOKEN_DATA_DETECTED",
            "@type": "error",
            "email": "jess@whatever.com",
            "user_id": "anonymous"
        },
        "content_type": "application/json",
        "status": 400
    },
    
    "401 (INVALID_AUTH_TOKEN_DATA_NOT_ACTIVATED_ACCOUNT_DETECTED)": {
        "content": {
            "@event": "INVALID_AUTH_TOKEN_DATA_NOT_ACTIVATED_ACCOUNT_DETECTED",
            "@type": "error",
            "user_id": 244
        },
        "content_type": "application/json",
        "status": 401
    }
}

/**
 * Examples for CREATE_FACEBOOK_BASED_AUTH_TOKEN
 */
export const CreateFacebookBasedAuthTokenExamples = {
    "201 (FACEBOOK_BASED_AUTH_TOKEN_CREATED)": {
        "content": {
            "@event": "FACEBOOK_BASED_AUTH_TOKEN_CREATED",
            "@type": "auth_token",
            "token": "access.token.1829"
        },
        "content_type": "application/json",
        "status": 201
    },
    
    "400 (BODY_DID_NOT_VALIDATE)": {
        "content": {
            "@event": "BODY_DID_NOT_VALIDATE",
            "@type": "error",
            "errors": {
                "code": [
                    "This field is required."
                ]
            },
            "user_id": "anonymous"
        },
        "content_type": "application/json",
        "status": 400
    },
    
    "500 (COULD_NOT_AUTHENTICATE_AGAINST_FACEBOOK)": {
        "content": {
            "@event": "COULD_NOT_AUTHENTICATE_AGAINST_FACEBOOK",
            "@type": "error",
            "user_id": "anonymous"
        },
        "content_type": "application/json",
        "status": 500
    }
}

/**
 * Examples for CREATE_FACEBOOK_BASED_MOBILE_AUTH_TOKEN
 */
export const CreateFacebookBasedMobileAuthTokenExamples = {
    "201 (FACEBOOK_BASED_MOBILE_AUTH_TOKEN_CREATED)": {
        "content": {
            "@event": "FACEBOOK_BASED_MOBILE_AUTH_TOKEN_CREATED",
            "@type": "auth_token",
            "token": "some.access.token.1234"
        },
        "content_type": "application/json",
        "status": 201
    },
    
    "400 (BODY_DID_NOT_VALIDATE)": {
        "content": {
            "@event": "BODY_DID_NOT_VALIDATE",
            "@type": "error",
            "errors": {
                "email": [
                    "This field is required."
                ]
            },
            "user_id": "anonymous"
        },
        "content_type": "application/json",
        "status": 400
    },
    
    "500 (COULD_NOT_AUTHENTICATE_AGAINST_FACEBOOK)": {
        "content": {
            "@event": "COULD_NOT_AUTHENTICATE_AGAINST_FACEBOOK",
            "@type": "error",
            "user_id": "anonymous"
        },
        "content_type": "application/json",
        "status": 500
    }
}

/**
 * Examples for CREATE_GOOGLE_BASED_AUTH_TOKEN
 */
export const CreateGoogleBasedAuthTokenExamples = {
    "201 (GOOGLE_BASED_AUTH_TOKEN_CREATED)": {
        "content": {
            "@event": "GOOGLE_BASED_AUTH_TOKEN_CREATED",
            "@type": "auth_token",
            "token": "access.token.1829"
        },
        "content_type": "application/json",
        "status": 201
    },
    
    "400 (BODY_DID_NOT_VALIDATE)": {
        "content": {
            "@event": "BODY_DID_NOT_VALIDATE",
            "@type": "error",
            "errors": {
                "code": [
                    "This field is required."
                ]
            },
            "user_id": "anonymous"
        },
        "content_type": "application/json",
        "status": 400
    },
    
    "500 (COULD_NOT_AUTHENTICATE_AGAINST_GOOGLE)": {
        "content": {
            "@event": "COULD_NOT_AUTHENTICATE_AGAINST_GOOGLE",
            "@type": "error",
            "user_id": "anonymous"
        },
        "content_type": "application/json",
        "status": 500
    }
}

/**
 * Examples for CREATE_GOOGLE_BASED_MOBILE_AUTH_TOKEN
 */
export const CreateGoogleBasedMobileAuthTokenExamples = {
    "201 (GOOGLE_BASED_MOBILE_AUTH_TOKEN_CREATED)": {
        "content": {
            "@event": "GOOGLE_BASED_MOBILE_AUTH_TOKEN_CREATED",
            "@type": "auth_token",
            "token": "some.access.token.1234"
        },
        "content_type": "application/json",
        "status": 201
    },
    
    "400 (BODY_DID_NOT_VALIDATE)": {
        "content": {
            "@event": "BODY_DID_NOT_VALIDATE",
            "@type": "error",
            "errors": {
                "email": [
                    "This field is required."
                ]
            },
            "user_id": "anonymous"
        },
        "content_type": "application/json",
        "status": 400
    },
    
    "500 (COULD_NOT_AUTHENTICATE_AGAINST_GOOGLE)": {
        "content": {
            "@event": "COULD_NOT_AUTHENTICATE_AGAINST_GOOGLE",
            "@type": "error",
            "user_id": "anonymous"
        },
        "content_type": "application/json",
        "status": 500
    }
}

/**
 * Examples for UPDATE_AUTH_TOKEN
 */
export const UpdateAuthTokenExamples = {
    "200 (AUTH_TOKEN_UPDATED)": {
        "content": {
            "@event": "AUTH_TOKEN_UPDATED",
            "@type": "auth_token",
            "token": "super.new.token.123"
        },
        "content_type": "application/json",
        "status": 200
    },
    
    "401 (COULD_NOT_FIND_USER)": {
        "content": {
            "@event": "COULD_NOT_FIND_USER",
            "@type": "error",
            "user_id": 547953
        },
        "content_type": "application/json",
        "status": 401
    },
    
    "403 (ACCESS_DENIED)": {
        "content": {
            "@event": "ACCESS_DENIED",
            "@type": "error",
            "user_id": "anonymous"
        },
        "content_type": "application/json",
        "status": 403
    }
}