/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */

/**
 * Geometries Management Domain Examples
 */

/**
 * Examples for BULK_READ_GEOMETRIES
 */
export const BulkReadGeometriesExamples = {
    "200 (GEOMETRIES_BULK_READ)": {
        "content": {
            "@event": "GEOMETRIES_BULK_READ",
            "@type": "geometries_list",
            "geometries": [
                {
                    "@type": "geometry",
                    "card_id": 1204,
                    "id": 1206,
                    "is_random": true,
                    "recall_score": 0.2,
                    "x": 0,
                    "y": 0
                },
                {
                    "@type": "geometry",
                    "card_id": 1205,
                    "id": 1207,
                    "is_random": true,
                    "recall_score": 0.4,
                    "x": 10,
                    "y": 11
                },
                {
                    "@type": "geometry",
                    "card_id": 1206,
                    "id": 1208,
                    "is_random": true,
                    "recall_score": 0.1,
                    "x": -5,
                    "y": 7
                },
                {
                    "@type": "geometry",
                    "card_id": 1207,
                    "id": 1209,
                    "is_random": true,
                    "recall_score": 0.8,
                    "x": 14,
                    "y": -9
                },
                {
                    "@type": "geometry",
                    "card_id": 1208,
                    "id": 1210,
                    "is_random": false,
                    "recall_score": 0.9,
                    "x": -22,
                    "y": 25
                },
                {
                    "@type": "geometry",
                    "card_id": 1209,
                    "id": 1211,
                    "is_random": false,
                    "recall_score": 1.0,
                    "x": -42,
                    "y": 45
                },
                {
                    "@type": "geometry",
                    "card_id": 1210,
                    "id": 1212,
                    "is_random": false,
                    "recall_score": 0.3,
                    "x": 31,
                    "y": 31
                },
                {
                    "@type": "geometry",
                    "card_id": 1211,
                    "id": 1213,
                    "is_random": false,
                    "recall_score": 0.4,
                    "x": -30,
                    "y": -27
                },
                {
                    "@type": "geometry",
                    "card_id": 1212,
                    "id": 1214,
                    "is_random": true,
                    "recall_score": 0.1,
                    "x": 23,
                    "y": -67
                },
                {
                    "@type": "geometry",
                    "card_id": 1213,
                    "id": 1215,
                    "is_random": true,
                    "recall_score": 0.8,
                    "x": 67,
                    "y": -21
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
                "height": [
                    "A valid number is required."
                ]
            },
            "user_id": 678
        },
        "content_type": "application/json",
        "status": 400
    }
}

/**
 * Examples for BULK_UPDATE_GEOMETRIES
 */
export const BulkUpdateGeometriesExamples = {
    "200 (GEOMETRIES_BULK_UPDATED)": {
        "content": {
            "@event": "GEOMETRIES_BULK_UPDATED",
            "@type": "geometries_list",
            "geometries": [
                {
                    "@type": "geometry",
                    "card_id": 1123,
                    "id": 1125,
                    "is_random": false,
                    "recall_score": null,
                    "x": 0,
                    "y": 0
                }
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
                "data": [
                    "Expected a list of items but got type \"str\"."
                ]
            },
            "user_id": 678
        },
        "content_type": "application/json",
        "status": 400
    }
}

/**
 * Examples for READ_GEOMETRY_BY_CARD
 */
export const ReadGeometryByCardExamples = {
    "200 (GEOMETRY_BY_CARD_READ)": {
        "content": {
            "@event": "GEOMETRY_BY_CARD_READ",
            "@type": "geometry",
            "card_id": 1095,
            "id": 1097,
            "is_random": false,
            "recall_score": null,
            "x": 3115,
            "y": 9597
        },
        "content_type": "application/json",
        "status": 200
    },
    
    "404 (COULD_NOT_FIND_GEOMETRY)": {
        "content": {
            "@event": "COULD_NOT_FIND_GEOMETRY",
            "@type": "error",
            "user_id": 678
        },
        "content_type": "application/json",
        "status": 404
    }
}

/**
 * Examples for READ_GRAPH
 */
export const ReadGraphExamples = {
    "200 (GRAPH_READ)": {
        "content": {
            "@event": "GRAPH_READ",
            "@type": "graph",
            "links": [
                {
                    "@type": "link",
                    "source": 1219,
                    "target": 1221,
                    "value": 0.46
                },
                {
                    "@type": "link",
                    "source": 1221,
                    "target": 1219,
                    "value": 0.68
                }
            ],
            "nodes": [
                {
                    "@type": "node",
                    "id": 1219,
                    "x": 3.0,
                    "y": 4.0
                },
                {
                    "@type": "node",
                    "id": 1221,
                    "x": 5.0,
                    "y": 78.0
                }
            ]
        },
        "content_type": "application/json",
        "status": 200
    }
}