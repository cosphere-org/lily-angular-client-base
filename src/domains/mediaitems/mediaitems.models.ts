/**
 * MediaItems Management Domain Models
 */

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/mediaitem/views.py/#lines-88
 */

export interface BulkReadMediaitemsQuery {
    limit?: number;
    offset?: number;
    order_by?: string;
    query?: string;
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/mediaitem/serializers.py/#lines-45
 */

export interface BulkReadMediaitemsResponse {
    mediaitems: {
        content_host?: string;
        content_uri?: string;
        created_timestamp: number;
        external_data?: Object;
        id: number;
        meta?: Object;
        size?: number;
        thumbnail_uri?: string;
        type: string;
        web_representations?: Object;
    }[];
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/mediaitem/views.py/#lines-266
 */

export interface DeleteMediaitemQuery {
    card_ids: number[];
    force_delete?: boolean;
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/.venv/src/lily/lily/base/serializers.py/#lines-158
 */

export interface DeleteMediaitemResponse {}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/mediaitem/serializers.py/#lines-8
 */

export interface ReadMediaitemResponse {
    content_host?: string;
    content_uri?: string;
    created_timestamp: number;
    external_data?: Object;
    id: number;
    meta?: Object;
    size?: number;
    thumbnail_uri?: string;
    type: string;
    web_representations?: Object;
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/mediaitem/serializers.py/#lines-8
 */

export interface ReadMediaitemByProcessIdResponse {
    content_host?: string;
    content_uri?: string;
    created_timestamp: number;
    external_data?: Object;
    id: number;
    meta?: Object;
    size?: number;
    thumbnail_uri?: string;
    type: string;
    web_representations?: Object;
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/mediaitem/parsers.py/#lines-72
 */

export interface ReadOrCreateMediaitemBody {
    card_ids: number[];
    content_host?: string;
    content_uri?: string;
    external_data: Object;
    is_card_type?: boolean;
    process_ids?: Object;
    type: string;
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/mediaitem/serializers.py/#lines-8
 */

export interface ReadOrCreateMediaitemResponse {
    content_host?: string;
    content_uri?: string;
    created_timestamp: number;
    external_data?: Object;
    id: number;
    meta?: Object;
    size?: number;
    thumbnail_uri?: string;
    type: string;
    web_representations?: Object;
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/mediaitem/parsers.py/#lines-99
 */

export interface UpdateMediaitemBody {
    card_ids: number[];
    content_host: string;
    content_uri: string;
    external_data: Object;
    type: string;
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/mediaitem/serializers.py/#lines-8
 */

export interface UpdateMediaitemResponse {
    content_host?: string;
    content_uri?: string;
    created_timestamp: number;
    external_data?: Object;
    id: number;
    meta?: Object;
    size?: number;
    thumbnail_uri?: string;
    type: string;
    web_representations?: Object;
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/mediaitem/views.py/#lines-338
 */

export interface UpdateMediaitemRepresentationBody {
    meta?: Object;
    text?: string;
    thumbnail_uri?: string;
    web_representations?: Object;
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/mediaitem/serializers.py/#lines-8
 */

export interface UpdateMediaitemRepresentationResponse {
    content_host?: string;
    content_uri?: string;
    created_timestamp: number;
    external_data?: Object;
    id: number;
    meta?: Object;
    size?: number;
    thumbnail_uri?: string;
    type: string;
    web_representations?: Object;
}