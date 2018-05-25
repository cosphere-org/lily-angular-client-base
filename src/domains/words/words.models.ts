/**
 * Words Management Domain Models
 */

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/word/views.py/#lines-31
 */

export interface BulkReadWordsQuery {
    first_character?: string;
    limit?: number;
    offset?: number;
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/word/serializers.py/#lines-19
 */

export interface BulkReadWordsResponse {
    words: {
        text: string;
    }[];
}