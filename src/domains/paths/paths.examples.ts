/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */

/**
 * Paths Management Domain Examples
 */

/**
 * Examples for BULK_DELETE_PATHS
 */
export const BulkDeletePathsExamples = {
    "200 (PATHS_BULK_DELETED)": {
        "content": {
            "@event": "PATHS_BULK_DELETED",
            "@type": "remove_summary",
            "summary": [
                {
                    "@type": "summary_entry",
                    "deleted": false,
                    "id": 288
                },
                {
                    "@type": "summary_entry",
                    "deleted": false,
                    "id": 292
                },
                {
                    "@type": "summary_entry",
                    "deleted": true,
                    "id": 290
                }
            ]
        },
        "content_type": "application/json",
        "status": 200
    },
    
    "400 (QUERY_DID_NOT_VALIDATE)": {
        "content": {
            "@event": "QUERY_DID_NOT_VALIDATE",
            "@type": "error",
            "errors": {
                "ids": [
                    "one must have at least one id to remove"
                ]
            },
            "user_id": 7890
        },
        "content_type": "application/json",
        "status": 400
    }
}

/**
 * Examples for BULK_READ_PATHS
 */
export const BulkReadPathsExamples = {
    "200 (PATHS_BULK_READ)": {
        "content": {
            "@event": "PATHS_BULK_READ",
            "@type": "paths_list",
            "paths": []
        },
        "content_type": "application/json",
        "status": 200
    },
    
    "400 (QUERY_DID_NOT_VALIDATE)": {
        "content": {
            "@event": "QUERY_DID_NOT_VALIDATE",
            "@type": "error",
            "errors": {
                "card_ids": [
                    "A valid integer is required."
                ]
            },
            "user_id": 11
        },
        "content_type": "application/json",
        "status": 400
    }
}

/**
 * Examples for CREATE_PATH
 */
export const CreatePathExamples = {
    "201 (PATH_CREATED)": {
        "content": {
            "@event": "PATH_CREATED",
            "@type": "path",
            "author_id": 7890,
            "cards": [],
            "id": 297,
            "ordered_card_ids": []
        },
        "content_type": "application/json",
        "status": 201
    },
    
    "400 (BODY_DID_NOT_VALIDATE)": {
        "content": {
            "@event": "BODY_DID_NOT_VALIDATE",
            "@type": "error",
            "errors": {
                "ordered_card_ids": [
                    "This field is required."
                ]
            },
            "user_id": 7890
        },
        "content_type": "application/json",
        "status": 400
    },
    
    "400 (BODY_JSON_DID_NOT_PARSE)": {
        "content": {
            "@event": "BODY_JSON_DID_NOT_PARSE",
            "@type": "error",
            "user_id": 7890
        },
        "content_type": "application/json",
        "status": 400
    },
    
    "404 (COULD_NOT_FIND_CARD)": {
        "content": {
            "@event": "COULD_NOT_FIND_CARD",
            "@type": "error",
            "user_id": 7890
        },
        "content_type": "application/json",
        "status": 404
    }
}

/**
 * Examples for READ_PATH
 */
export const ReadPathExamples = {
    "200 (PATH_READ)": {
        "content": {
            "@event": "PATH_READ",
            "@type": "path",
            "author_id": 7890,
            "cards": [
                {
                    "@type": "card",
                    "author_id": 7890,
                    "created_timestamp": 1528833159.546103,
                    "external_app_uri": null,
                    "hashtags": [],
                    "id": 1743,
                    "paths_count": null,
                    "source": {
                        "@type": "side",
                        "cells": [
                            {
                                "html": "Totam porro nesciunt quas totam.",
                                "id": "56678mefd",
                                "name": "text cell",
                                "style": {
                                    "backgroundColor": "transparent",
                                    "color": "#fff",
                                    "fontSize": "150%",
                                    "height": "auto",
                                    "left": "30px",
                                    "textAlign": "left",
                                    "top": "0px",
                                    "width": "100px",
                                    "zIndex": 1
                                },
                                "subtype": "PARAGRAPH",
                                "type": "TEXT"
                            }
                        ],
                        "style": {}
                    },
                    "target": {
                        "@type": "side",
                        "cells": [
                            {
                                "html": "Similique consequuntur eveniet provident.",
                                "id": "56678mefd",
                                "name": "text cell",
                                "style": {
                                    "backgroundColor": "transparent",
                                    "color": "#fff",
                                    "fontSize": "150%",
                                    "height": "auto",
                                    "left": "30px",
                                    "textAlign": "left",
                                    "top": "0px",
                                    "width": "100px",
                                    "zIndex": 1
                                },
                                "subtype": "PARAGRAPH",
                                "type": "TEXT"
                            }
                        ],
                        "style": {}
                    },
                    "updated_timestamp": 1528833159.542007
                },
                {
                    "@type": "card",
                    "author_id": 7890,
                    "created_timestamp": 1528833159.556542,
                    "external_app_uri": null,
                    "hashtags": [],
                    "id": 1744,
                    "paths_count": null,
                    "source": {
                        "@type": "side",
                        "cells": [
                            {
                                "html": "Corporis aperiam expedita perferendis ullam nostrum expedita nihil.",
                                "id": "56678mefd",
                                "name": "text cell",
                                "style": {
                                    "backgroundColor": "transparent",
                                    "color": "#fff",
                                    "fontSize": "150%",
                                    "height": "auto",
                                    "left": "30px",
                                    "textAlign": "left",
                                    "top": "0px",
                                    "width": "100px",
                                    "zIndex": 1
                                },
                                "subtype": "PARAGRAPH",
                                "type": "TEXT"
                            }
                        ],
                        "style": {}
                    },
                    "target": {
                        "@type": "side",
                        "cells": [
                            {
                                "html": "Velit mollitia cupiditate laboriosam voluptatem.",
                                "id": "56678mefd",
                                "name": "text cell",
                                "style": {
                                    "backgroundColor": "transparent",
                                    "color": "#fff",
                                    "fontSize": "150%",
                                    "height": "auto",
                                    "left": "30px",
                                    "textAlign": "left",
                                    "top": "0px",
                                    "width": "100px",
                                    "zIndex": 1
                                },
                                "subtype": "PARAGRAPH",
                                "type": "TEXT"
                            }
                        ],
                        "style": {}
                    },
                    "updated_timestamp": 1528833159.553387
                }
            ],
            "id": 298,
            "ordered_card_ids": [
                1743,
                1744
            ]
        },
        "content_type": "application/json",
        "status": 200
    },
    
    "404 (COULD_NOT_FIND_PATH)": {
        "content": {
            "@event": "COULD_NOT_FIND_PATH",
            "@type": "error",
            "user_id": 7890
        },
        "content_type": "application/json",
        "status": 404
    }
}

/**
 * Examples for UPDATE_PATH
 */
export const UpdatePathExamples = {
    "200 (PATH_UPDATED)": {
        "content": {
            "@event": "PATH_UPDATED",
            "@type": "path",
            "author_id": 7890,
            "cards": [
                {
                    "@type": "card",
                    "author_id": 7890,
                    "created_timestamp": 1528833159.758992,
                    "external_app_uri": null,
                    "hashtags": [],
                    "id": 1751,
                    "paths_count": null,
                    "source": {
                        "@type": "side",
                        "cells": [
                            {
                                "html": "Necessitatibus optio quisquam vel debitis natus fugiat.",
                                "id": "56678mefd",
                                "name": "text cell",
                                "style": {
                                    "backgroundColor": "transparent",
                                    "color": "#fff",
                                    "fontSize": "150%",
                                    "height": "auto",
                                    "left": "30px",
                                    "textAlign": "left",
                                    "top": "0px",
                                    "width": "100px",
                                    "zIndex": 1
                                },
                                "subtype": "PARAGRAPH",
                                "type": "TEXT"
                            }
                        ],
                        "style": {}
                    },
                    "target": {
                        "@type": "side",
                        "cells": [
                            {
                                "html": "Quod blanditiis nam omnis pariatur maxime.",
                                "id": "56678mefd",
                                "name": "text cell",
                                "style": {
                                    "backgroundColor": "transparent",
                                    "color": "#fff",
                                    "fontSize": "150%",
                                    "height": "auto",
                                    "left": "30px",
                                    "textAlign": "left",
                                    "top": "0px",
                                    "width": "100px",
                                    "zIndex": 1
                                },
                                "subtype": "PARAGRAPH",
                                "type": "TEXT"
                            }
                        ],
                        "style": {}
                    },
                    "updated_timestamp": 1528833159.755668
                }
            ],
            "id": 302,
            "ordered_card_ids": [
                1751
            ]
        },
        "content_type": "application/json",
        "status": 200
    },
    
    "400 (BODY_DID_NOT_VALIDATE)": {
        "content": {
            "@event": "BODY_DID_NOT_VALIDATE",
            "@type": "error",
            "errors": {
                "ordered_card_ids": [
                    "This field is required."
                ]
            },
            "user_id": 7890
        },
        "content_type": "application/json",
        "status": 400
    },
    
    "400 (BODY_JSON_DID_NOT_PARSE)": {
        "content": {
            "@event": "BODY_JSON_DID_NOT_PARSE",
            "@type": "error",
            "user_id": 7890
        },
        "content_type": "application/json",
        "status": 400
    },
    
    "403 (AUTHORISHIP_LOCKED_PATH_DETECTED)": {
        "content": {
            "@event": "AUTHORISHIP_LOCKED_PATH_DETECTED",
            "@type": "error",
            "path_id": "306",
            "user_id": 7890
        },
        "content_type": "application/json",
        "status": 403
    },
    
    "404 (COULD_NOT_FIND_CARD)": {
        "content": {
            "@event": "COULD_NOT_FIND_CARD",
            "@type": "error",
            "user_id": 7890
        },
        "content_type": "application/json",
        "status": 404
    },
    
    "404 (COULD_NOT_FIND_PATH)": {
        "content": {
            "@event": "COULD_NOT_FIND_PATH",
            "@type": "error",
            "user_id": 7890
        },
        "content_type": "application/json",
        "status": 404
    }
}