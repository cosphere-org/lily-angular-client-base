/**
 * Fragments Management Domain Models
 */

/**
 * https://bitbucket.org/goodai/cosphere-fragment-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/.venv/src/lily/lily/base/serializers.py/#lines-158
 */

export interface PublishFragmentResponse {}

/**
 * https://bitbucket.org/goodai/cosphere-fragment-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_fragment_service/fragment/serializers.py/#lines-50
 */

export interface CreateFragmentResponse {
    description: string;
    id?: number;
    is_author: boolean;
    is_learner: boolean;
    is_premium?: boolean;
    is_published?: boolean;
    title: string;
}

/**
 * https://bitbucket.org/goodai/cosphere-fragment-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/.venv/src/lily/lily/base/serializers.py/#lines-158
 */

export interface MergeFragmentResponse {}

/**
 * https://bitbucket.org/goodai/cosphere-fragment-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_fragment_service/fragment/views/crud.py/#lines-199
 */

export interface UpdateFragmentBody {
    card_ids: number[];
    description: string;
    is_premium?: boolean;
    path_ids: number[];
    title: string;
}

/**
 * https://bitbucket.org/goodai/cosphere-fragment-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/.venv/src/lily/lily/base/serializers.py/#lines-158
 */

export interface UpdateFragmentResponse {}

/**
 * https://bitbucket.org/goodai/cosphere-fragment-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_fragment_service/fragment/serializers.py/#lines-175
 */

export interface ReadFragmentSampleResponse {
    cards: Object[];
}

/**
 * https://bitbucket.org/goodai/cosphere-fragment-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/.venv/src/lily/lily/base/serializers.py/#lines-158
 */

export interface DeleteFragmentResponse {}

/**
 * https://bitbucket.org/goodai/cosphere-fragment-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_fragment_service/fragment/serializers.py/#lines-127
 */

export interface ReadFragmentResponse {
    cards_life_cycles: Object[];
    description: string;
    id?: number;
    is_author: boolean;
    is_learner: boolean;
    is_premium?: boolean;
    is_published?: boolean;
    links_life_cycles: Object[];
    paths_life_cycles: Object[];
    title: string;
}

/**
 * https://bitbucket.org/goodai/cosphere-fragment-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_fragment_service/fragment/views/public.py/#lines-26
 */

export interface BulkReadPublishedFragmentsQuery {
    limit?: number;
    offset?: number;
    query?: string;
}

/**
 * https://bitbucket.org/goodai/cosphere-fragment-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_fragment_service/fragment/serializers.py/#lines-43
 */

export interface BulkReadPublishedFragmentsResponse {
    fragments: {
        description: string;
        id?: number;
        is_premium?: boolean;
        title: string;
    }[];
}

/**
 * https://bitbucket.org/goodai/cosphere-fragment-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_fragment_service/fragment/views/crud.py/#lines-78
 */

export interface BulkReadFragmentsQuery {
    ids: number[];
    is_author?: boolean;
    is_learner?: boolean;
    limit?: number;
    offset?: number;
    query?: string;
}

/**
 * https://bitbucket.org/goodai/cosphere-fragment-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_fragment_service/fragment/serializers.py/#lines-108
 */

export interface BulkReadFragmentsResponse {
    fragments: {
        description: string;
        id?: number;
        is_author: boolean;
        is_learner: boolean;
        is_premium?: boolean;
        is_published?: boolean;
        title: string;
    }[];
}

/**
 * https://bitbucket.org/goodai/cosphere-fragment-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_fragment_service/fragment/serializers.py/#lines-150
 */

export interface ReadFragmentDiffResponse {
    created_card_ids: number[];
    created_path_ids: number[];
    prod_text_representation: {
        description?: string;
        title?: string;
    };
    stage_text_representation: {
        description?: string;
        title?: string;
    };
    updated_card_ids: number[];
    updated_path_ids: number[];
}