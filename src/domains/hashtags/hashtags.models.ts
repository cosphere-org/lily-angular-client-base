/**
 * Hashtags Management Domain Models
 */

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/hashtag/views.py/#lines-190
 */

export interface ReadHashtagsTocQuery {
    limit?: number;
    offset?: number;
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/hashtag/serializers.py/#lines-28
 */

export interface ReadHashtagsTocResponse {
    hashtags: {
        count: number;
        id?: number;
        normalized_text: string;
        text: string;
    }[];
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/hashtag/views.py/#lines-32
 */

export interface CreateHashtagBody {
    card_ids: number[];
    text: string;
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/hashtag/serializers.py/#lines-8
 */

export interface CreateHashtagResponse {
    count: number;
    id?: number;
    normalized_text: string;
    text: string;
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/hashtag/views.py/#lines-150
 */

export interface DeleteHashtagQuery {
    card_ids: number[];
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/.venv/src/lily/lily/base/serializers.py/#lines-158
 */

export interface DeleteHashtagResponse {}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/hashtag/views.py/#lines-119
 */

export interface UpdateHashtagBody {
    card_ids: number[];
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/.venv/src/lily/lily/base/serializers.py/#lines-158
 */

export interface UpdateHashtagResponse {}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/hashtag/views.py/#lines-64
 */

export interface BulkReadHashtagsQuery {
    first_character?: string;
    limit?: number;
    offset?: number;
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/hashtag/serializers.py/#lines-28
 */

export interface BulkReadHashtagsResponse {
    hashtags: {
        count: number;
        id?: number;
        normalized_text: string;
        text: string;
    }[];
}