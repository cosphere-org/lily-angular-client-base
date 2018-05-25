/**
 * Attempt Stats Management Domain Models
 */

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/recall/views.py/#lines-232
 */

export interface BulkReadAttemptstatsQuery {
    call_chain?: string;
    limit?: number;
    offset?: number;
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/recall/serializers.py/#lines-57
 */

export interface BulkReadAttemptstatsResponse {
    attempt_stats: {
        card_id?: any;
        created_timestamp: number;
        id?: number;
        states_path?: Object;
        successful?: boolean;
    }[];
    count: number;
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/recall/views.py/#lines-189
 */

export interface CreateAttemptstatBody {
    attempt_id?: number;
    card_id: number;
    states_path: Object;
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/recall/serializers.py/#lines-36
 */

export interface CreateAttemptstatResponse {
    card_id?: any;
    created_timestamp: number;
    id?: number;
    states_path?: Object;
    successful?: boolean;
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/recall/views.py/#lines-289
 */

export interface CreateExternalAttemptStatBody {
    states_path: Object;
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/recall/serializers.py/#lines-36
 */

export interface CreateExternalAttemptStatResponse {
    card_id?: any;
    created_timestamp: number;
    id?: number;
    states_path?: Object;
    successful?: boolean;
}