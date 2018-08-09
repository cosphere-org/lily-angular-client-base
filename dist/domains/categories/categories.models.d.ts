/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
/**
 * Categories Management Domain Models
 */
/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b8dec3cf13d1897109220787f995546558de477d/cosphere_entity_service/category/serializers.py/#lines-27
 */
export declare enum BulkReadCategoriesResponseText {
    FORGOTTEN = "FORGOTTEN",
    HOT = "HOT",
    NOT_RECALLED = "NOT_RECALLED",
    PROBLEMATIC = "PROBLEMATIC",
    RECENTLY_ADDED = "RECENTLY_ADDED",
}
export interface BulkReadCategoriesResponseEntity {
    count: number;
    id?: number;
    text: BulkReadCategoriesResponseText;
}
export interface BulkReadCategoriesResponse {
    data: BulkReadCategoriesResponseEntity[];
}