/**
 * Fragment Words Management Domain Models
 */

/**
 * https://bitbucket.org/goodai/cosphere-fragment-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_fragment_service/word/views.py/#lines-30
 */

export interface BulkReadPublishedFragmentWordsQuery {
    first_character?: string;
    limit?: number;
    offset?: number;
}

/**
 * https://bitbucket.org/goodai/cosphere-fragment-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_fragment_service/word/serializers.py/#lines-33
 */

export interface BulkReadPublishedFragmentWordsResponse {
    words: {
        count: number;
        id?: number;
        text: string;
    }[];
}

/**
 * https://bitbucket.org/goodai/cosphere-fragment-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_fragment_service/word/views.py/#lines-30
 */

export interface BulkReadFragmentWordsQuery {
    first_character?: string;
    limit?: number;
    offset?: number;
}

/**
 * https://bitbucket.org/goodai/cosphere-fragment-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_fragment_service/word/serializers.py/#lines-33
 */

export interface BulkReadFragmentWordsResponse {
    words: {
        count: number;
        id?: number;
        text: string;
    }[];
}