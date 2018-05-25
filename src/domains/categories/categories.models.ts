/**
 * Categories Management Domain Models
 */

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_entity_service/category/serializers.py/#lines-27
 */

export enum BulkReadCategoriesResponseText {
    FORGOTTEN = 'FORGOTTEN',
    HOT = 'HOT',
    NOT_RECALLED = 'NOT_RECALLED',
    PROBLEMATIC = 'PROBLEMATIC',
    RECENTLY_ADDED = 'RECENTLY_ADDED',
}

export interface BulkReadCategoriesResponse {
    categories: {
        count: number;
        id?: number;
        text: BulkReadCategoriesResponseText;
    }[];
}