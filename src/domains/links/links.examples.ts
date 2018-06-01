/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */

/**
 * Links Management Domain Examples
 */

/**
 * Examples for DELETE_LINK
 */
export const DeleteLinkExamples = {
    "200 (LINK_DELETED)": {
        "content": {
            "@event": "LINK_DELETED",
            "@type": "empty"
        },
        "content_type": "application/json",
        "status": 200
    },
    
    "404 (COULD_NOT_FIND_CARD)": {
        "content": {
            "@event": "COULD_NOT_FIND_CARD",
            "@type": "error",
            "user_id": 678
        },
        "content_type": "application/json",
        "status": 404
    }
}

/**
 * Examples for READ_OR_CREATE_LINK
 */
export const ReadOrCreateLinkExamples = {
    "200 (LINK_READ)": {
        "content": {
            "@event": "LINK_READ",
            "@type": "link",
            "author_id": 78,
            "created_timestamp": 1527800162.674778,
            "from_card_id": 1077,
            "id": 442,
            "kind": "CARD",
            "reference_id": 9713,
            "to_card_id": 1078,
            "value": 1.0
        },
        "content_type": "application/json",
        "status": 200
    },
    
    "201 (LINK_CREATED)": {
        "content": {
            "@event": "LINK_CREATED",
            "@type": "link",
            "author_id": 78,
            "created_timestamp": 1527800162.978955,
            "from_card_id": 1082,
            "id": 445,
            "kind": "CARD",
            "reference_id": 1082,
            "to_card_id": 1081,
            "value": 1.0
        },
        "content_type": "application/json",
        "status": 201
    },
    
    "400 (BODY_DID_NOT_VALIDATE)": {
        "content": {
            "@event": "BODY_DID_NOT_VALIDATE",
            "@type": "error",
            "errors": {
                "to_card_id": [
                    "This field is required."
                ]
            },
            "user_id": 78
        },
        "content_type": "application/json",
        "status": 400
    },
    
    "404 (COULD_NOT_FIND_CARD)": {
        "content": {
            "@event": "COULD_NOT_FIND_CARD",
            "@type": "error",
            "user_id": 78
        },
        "content_type": "application/json",
        "status": 404
    }
}