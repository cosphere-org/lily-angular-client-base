/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */

/**
 * Attempt Stats Management Domain Models
 */

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/5f215fabba7fa3925151c098fad0051162452821/cosphere_entity_service/recall/views.py/#lines-231
 */

export interface BulkReadAttemptstatsQuery {
    created_timestamp__gte?: number;
    limit?: number;
    offset?: number;
    order_by?: string;
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/5f215fabba7fa3925151c098fad0051162452821/cosphere_entity_service/recall/serializers.py/#lines-57
 */

export interface BulkReadAttemptstatsResponse {
    at__count: number;
    attempt_stats: {
        card_id?: any;
        created_timestamp: number;
        id?: number;
        states_path?: Object;
        successful?: boolean;
    }[];
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/5f215fabba7fa3925151c098fad0051162452821/cosphere_entity_service/recall/views.py/#lines-188
 */

export interface CreateAttemptstatBody {
    attempt_id?: number;
    card_id: number;
    states_path: Object;
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/5f215fabba7fa3925151c098fad0051162452821/cosphere_entity_service/recall/serializers.py/#lines-36
 */

export interface CreateAttemptstatResponse {
    card_id?: any;
    created_timestamp: number;
    id?: number;
    states_path?: Object;
    successful?: boolean;
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/5f215fabba7fa3925151c098fad0051162452821/cosphere_entity_service/recall/views.py/#lines-281
 */

export interface CreateExternalAttemptStatBody {
    states_path: Object;
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/5f215fabba7fa3925151c098fad0051162452821/cosphere_entity_service/recall/serializers.py/#lines-36
 */

export interface CreateExternalAttemptStatResponse {
    card_id?: any;
    created_timestamp: number;
    id?: number;
    states_path?: Object;
    successful?: boolean;
}