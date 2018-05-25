/**
 * Attempts Management Domain Models
 */

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/recall/serializers.py/#lines-29
 */

export interface BulkReadAttemptsByCardsResponse {
    attempts: {
        card_id: number;
        cells?: Object;
        id?: number;
        style?: Object;
    }[];
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/recall/views.py/#lines-89
 */

export interface CreateAttemptBody {
    card_id: number;
    cells: Object;
    style?: Object;
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/recall/serializers.py/#lines-9
 */

export interface CreateAttemptResponse {
    card_id: number;
    cells?: Object;
    id?: number;
    style?: Object;
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/recall/views.py/#lines-61
 */

export interface UpdateAttemptBody {
    cells: Object;
    style?: Object;
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/recall/serializers.py/#lines-9
 */

export interface UpdateAttemptResponse {
    card_id: number;
    cells?: Object;
    id?: number;
    style?: Object;
}