/**
 * Paths Management Domain Models
 */

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/path/views.py/#lines-161
 */

export interface BulkDeletePathsQuery {
    ids: number[];
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/path/views.py/#lines-172
 */

export interface BulkDeletePathsResponse {
    summary: {
        deleted: boolean;
        id: number;
    }[];
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/path/views.py/#lines-103
 */

export interface BulkReadPathsQuery {
    card_ids: number[];
    category_id?: number;
    ids: number[];
    limit?: number;
    offset?: number;
    query?: string;
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/path/serializers.py/#lines-42
 */

export interface BulkReadPathsResponse {
    paths: {
        author_id?: any;
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
        id?: number;
        ordered_card_ids?: Object;
    }[];
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/path/views.py/#lines-61
 */

export interface CreatePathBody {
    ordered_card_ids: number[];
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/path/serializers.py/#lines-9
 */

export interface CreatePathResponse {
    author_id?: any;
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
    id?: number;
    ordered_card_ids?: Object;
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/path/serializers.py/#lines-9
 */

export interface ReadPathResponse {
    author_id?: any;
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
    id?: number;
    ordered_card_ids?: Object;
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/path/views.py/#lines-61
 */

export interface UpdatePathBody {
    ordered_card_ids: number[];
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/path/serializers.py/#lines-9
 */

export interface UpdatePathResponse {
    author_id?: any;
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
    id?: number;
    ordered_card_ids?: Object;
}