/**
 * Recall Management Domain Models
 */

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/recall/views.py/#lines-369
 */

export interface CreateRecallSessionBody {
    card_ids: number[];
    category_id?: number;
    fragment_id?: number;
    path_ids: number[];
    prev_ids: number[];
    query?: string;
    size?: number;
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/recall/serializers.py/#lines-66
 */

export interface CreateRecallSessionResponse {
    cards: {
        author_id?: any;
        created_timestamp: number;
        external_app_uri?: string;
        hashtags: {
            count: number;
            id?: number;
            normalized_text: string;
            text: string;
        }[];
        id?: number;
        paths_count: number;
        source: {
            cells?: Object;
            style?: Object;
        };
        target: {
            cells?: Object;
            style?: Object;
        };
        updated_timestamp: number;
    }[];
    terminate: boolean;
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/recall/serializers.py/#lines-75
 */

export interface ReadRecallSummaryResponse {
    summary: {
        count: number;
        score: number;
    }[];
    total: number;
}