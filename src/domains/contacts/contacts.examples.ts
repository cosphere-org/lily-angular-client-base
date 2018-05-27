/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */

/**
 * Contact Management Domain Examples
 */

/**
 * Examples for CREATE_ANONYMOUS_CONTACT_ATTEMPT
 */
export const CreateAnonymousContactAttemptExamples = {
    "201 (ANONYMOUS_CONTACT_ATTEMPT_CREATED)": {
        "content": {
            "@event": "ANONYMOUS_CONTACT_ATTEMPT_CREATED",
            "@type": "empty"
        },
        "content_type": "application/json",
        "status": 201
    },
    
    "400 (BODY_DID_NOT_VALIDATE)": {
        "content": {
            "@event": "BODY_DID_NOT_VALIDATE",
            "@type": "error",
            "errors": {
                "text": [
                    "This field is required."
                ]
            },
            "user_id": "anonymous"
        },
        "content_type": "application/json",
        "status": 400
    }
}

/**
 * Examples for SEND_AUTHENTICATED_CONTACT_MESSAGE
 */
export const SendAuthenticatedContactMessageExamples = {
    "200 (AUTHENTICATED_CONTACT_MESSAGE_SENT)": {
        "content": {
            "@event": "AUTHENTICATED_CONTACT_MESSAGE_SENT",
            "@type": "empty"
        },
        "content_type": "application/json",
        "status": 200
    },
    
    "400 (BODY_DID_NOT_VALIDATE)": {
        "content": {
            "@event": "BODY_DID_NOT_VALIDATE",
            "@type": "error",
            "errors": {
                "text": [
                    "This field is required."
                ]
            },
            "user_id": 296
        },
        "content_type": "application/json",
        "status": 400
    },
    
    "401 (COULD_NOT_FIND_USER)": {
        "content": {
            "@event": "COULD_NOT_FIND_USER",
            "@type": "error",
            "user_id": 685965
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
    },
    
    "500 (GENERIC_ERROR_OCCURRED)": {
        "content": {
            "@event": "GENERIC_ERROR_OCCURRED",
            "@type": "error",
            "errors": [
                "'InputAttrs' object has no attribute 'user'"
            ],
            "user_id": 685965
        },
        "content_type": "application/json",
        "status": 500
    }
}

/**
 * Examples for VERIFY_ANONYMOUS_CONTACT_ATTEMPT
 */
export const VerifyAnonymousContactAttemptExamples = {
    "200 (ANONYMOUS_CONTACT_ATTEMPT_VERIFIED)": {
        "content": {
            "@event": "ANONYMOUS_CONTACT_ATTEMPT_VERIFIED",
            "@type": "empty"
        },
        "content_type": "application/json",
        "status": 200
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
    }
}