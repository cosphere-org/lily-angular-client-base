/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */

/**
 * Cards Management Domain Examples
 */

/**
 * Examples for BULK_DELETE_CARDS
 */
export const BulkDeleteCardsExamples = {
    "200 (CARDS_BULK_DELETED)": {
        "content": {
            "@event": "CARDS_BULK_DELETED",
            "@type": "remove_summary",
            "summary": [
                {
                    "@type": "summary_entry",
                    "deleted": false,
                    "id": 33
                },
                {
                    "@type": "summary_entry",
                    "deleted": false,
                    "id": 34
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
            "user_id": 891
        },
        "content_type": "application/json",
        "status": 400
    }
}

/**
 * Examples for BULK_READ_CARDS
 */
export const BulkReadCardsExamples = {
    "200 (CARDS_BULK_READ)": {
        "content": {
            "@event": "CARDS_BULK_READ",
            "@type": "cards_list",
            "cards": [
                {
                    "@type": "card",
                    "author_id": 11,
                    "created_timestamp": 1528833080.218115,
                    "external_app_uri": null,
                    "hashtags": [],
                    "id": 46,
                    "paths_count": null,
                    "source": {
                        "@type": "side",
                        "cells": [
                            {
                                "html": "#h0",
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
                                "html": "#h1",
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
                    "updated_timestamp": 1528833080.215527
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
                "offset": [
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
 * Examples for CREATE_CARD
 */
export const CreateCardExamples = {
    "201 (CARD_CREATED)": {
        "content": {
            "@event": "CARD_CREATED",
            "@type": "card",
            "author_id": 891,
            "created_timestamp": 1528833079.826792,
            "external_app_uri": null,
            "hashtags": [],
            "id": 35,
            "paths_count": null,
            "source": {
                "@type": "side",
                "cells": [
                    {
                        "html": "some source cells",
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
                "style": {
                    "backgroundColor": "gray"
                }
            },
            "target": {
                "@type": "side",
                "cells": [
                    {
                        "html": "some target cells",
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
            "updated_timestamp": 1528833079.824267
        },
        "content_type": "application/json",
        "status": 201
    },
    
    "400 (BODY_DID_NOT_VALIDATE)": {
        "content": {
            "@event": "BODY_DID_NOT_VALIDATE",
            "@type": "error",
            "errors": {
                "source": [
                    "This field is required."
                ],
                "target": [
                    "This field is required."
                ]
            },
            "user_id": 891
        },
        "content_type": "application/json",
        "status": 400
    }
}

/**
 * Examples for READ_CARD
 */
export const ReadCardExamples = {
    "200 (CARD_READ)": {
        "content": {
            "@event": "CARD_READ",
            "@type": "card",
            "author_id": 9067,
            "created_timestamp": 1528833078.443715,
            "external_app_uri": null,
            "hashtags": [],
            "id": 7,
            "paths_count": null,
            "source": {
                "@type": "side",
                "cells": [
                    {
                        "html": "Vel iusto corporis nam quaerat occaecati aliquam saepe.",
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
                        "html": "Laborum accusamus voluptates debitis dignissimos eligendi.",
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
            "updated_timestamp": 1528833078.437735
        },
        "content_type": "application/json",
        "status": 200
    },
    
    "404 (COULD_NOT_FIND_CARD)": {
        "content": {
            "@event": "COULD_NOT_FIND_CARD",
            "@type": "error",
            "user_id": 891
        },
        "content_type": "application/json",
        "status": 404
    }
}

/**
 * Examples for UPDATE_CARD
 */
export const UpdateCardExamples = {
    "200 (CARD_UPDATED)": {
        "content": {
            "@event": "CARD_UPDATED",
            "@type": "card",
            "author_id": 891,
            "created_timestamp": 1528833079.054681,
            "external_app_uri": null,
            "hashtags": [],
            "id": 14,
            "paths_count": null,
            "source": {
                "@type": "side",
                "cells": [
                    {
                        "html": "some stuff",
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
                        "html": "some #NOThashtag",
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
                    },
                    {
                        "html": "some more #NOThashtag #wat",
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
                "style": {
                    "backgroundColor": "red"
                }
            },
            "updated_timestamp": 1528833079.103805
        },
        "content_type": "application/json",
        "status": 200
    },
    
    "400 (BODY_DID_NOT_VALIDATE)": {
        "content": {
            "@event": "BODY_DID_NOT_VALIDATE",
            "@type": "error",
            "errors": {
                "target": {
                    "cells": [
                        {
                            "cell_idx": "0",
                            "error": "'not.valid' does not match '^\\\\-?\\\\d+(\\\\.\\\\d+)?px$'",
                            "path": [
                                "properties",
                                "style",
                                "properties",
                                "left",
                                "pattern"
                            ]
                        }
                    ]
                }
            },
            "user_id": 891
        },
        "content_type": "application/json",
        "status": 400
    },
    
    "403 (AUTHORISHIP_LOCKED_CARD_DETECTED)": {
        "content": {
            "@event": "AUTHORISHIP_LOCKED_CARD_DETECTED",
            "@type": "error",
            "card_id": "17",
            "user_id": 891
        },
        "content_type": "application/json",
        "status": 403
    },
    
    "404 (COULD_NOT_FIND_CARD)": {
        "content": {
            "@event": "COULD_NOT_FIND_CARD",
            "@type": "error",
            "user_id": 891
        },
        "content_type": "application/json",
        "status": 404
    }
}