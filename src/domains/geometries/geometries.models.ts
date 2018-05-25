/**
 * Geometries Management Domain Models
 */

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/grid/views.py/#lines-188
 */

export interface BulkUpdateGeometriesBody {
    data: Object[];
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/grid/serializers.py/#lines-55
 */

export interface BulkUpdateGeometriesResponse {
    geometries: {
        card_id?: any;
        id?: number;
        is_random?: boolean;
        recall_score?: number;
        x?: number;
        y?: number;
    }[];
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/grid/views.py/#lines-149
 */

export interface BulkReadGeometriesQuery {
    height?: number;
    width?: number;
    x?: number;
    y?: number;
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/grid/serializers.py/#lines-55
 */

export interface BulkReadGeometriesResponse {
    geometries: {
        card_id?: any;
        id?: number;
        is_random?: boolean;
        recall_score?: number;
        x?: number;
        y?: number;
    }[];
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/grid/serializers.py/#lines-39
 */

export interface ReadGeometryByCardResponse {
    card_id?: any;
    id?: number;
    is_random?: boolean;
    recall_score?: number;
    x?: number;
    y?: number;
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/grid/views.py/#lines-149
 */

export interface ReadGraphQuery {
    card_ids: number[];
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/grid/serializers.py/#lines-62
 */

export interface ReadGraphResponse {
    links: {
        source: number;
        target: number;
        value: number;
    }[];
    nodes: {
        id: number;
        x: number;
        y: number;
    }[];
}