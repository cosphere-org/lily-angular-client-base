/**
 * Fragment Hashtags Management Domain Models
 */

/**
 * https://bitbucket.org/goodai/cosphere-fragment-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_fragment_service/hashtag/views.py/#lines-29
 */

export interface BulkReadPublishedFragmentHashtagsQuery {
    first_character?: string;
    limit?: number;
    offset?: number;
}

/**
 * https://bitbucket.org/goodai/cosphere-fragment-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_fragment_service/hashtag/serializers.py/#lines-33
 */

export interface BulkReadPublishedFragmentHashtagsResponse {
    hashtags: {
        count: number;
        id?: number;
        text: string;
    }[];
}

/**
 * https://bitbucket.org/goodai/cosphere-fragment-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_fragment_service/hashtag/views.py/#lines-29
 */

export interface BulkReadFragmentHashtagsQuery {
    first_character?: string;
    limit?: number;
    offset?: number;
}

/**
 * https://bitbucket.org/goodai/cosphere-fragment-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_fragment_service/hashtag/serializers.py/#lines-33
 */

export interface BulkReadFragmentHashtagsResponse {
    hashtags: {
        count: number;
        id?: number;
        text: string;
    }[];
}