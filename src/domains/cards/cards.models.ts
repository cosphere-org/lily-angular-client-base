/**
 * Cards Management Domain Models
 */

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/card/views.py/#lines-274
 */

export interface BulkDeleteCardsQuery {
    ids: number[];
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/card/views.py/#lines-285
 */

export interface BulkDeleteCardsResponse {
    summary: {
        deleted: boolean;
        id: number;
    }[];
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/card/views.py/#lines-221
 */

export interface BulkReadCardsQuery {
    category_id?: number;
    ids: number[];
    limit?: number;
    offset?: number;
    query?: string;
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/card/serializers.py/#lines-69
 */

export interface BulkReadCardsResponse {
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
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/card/views.py/#lines-179
 */

export interface CreateCardBody {
    source: {
        cells: Object;
        style?: Object;
    };
    target: {
        cells: Object;
        style?: Object;
    };
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/card/serializers.py/#lines-21
 */

export interface CreateCardResponse {
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
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/card/serializers.py/#lines-21
 */

export interface ReadCardResponse {
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
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/card/views.py/#lines-66
 */

export interface UpdateCardBody {
    external_app_uri?: string;
    source?: {
        cells: Object;
        style?: Object;
    };
    target?: {
        cells: Object;
        style?: Object;
    };
    terms: string[];
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/card/serializers.py/#lines-21
 */

export interface UpdateCardResponse {
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
}