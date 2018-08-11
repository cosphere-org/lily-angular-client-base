/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
/**
 * Fragment Words Management Domain Models
 */
/**
 * https://bitbucket.org/goodai/cosphere-fragment-service/src/3709b52e6d7c7399154582e8055c0e76139a4c00/cosphere_fragment_service/word/views.py/#lines-30
 */
export interface BulkReadFragmentWordsQuery {
    first_character?: string;
    limit?: number;
    offset?: number;
}
/**
 * https://bitbucket.org/goodai/cosphere-fragment-service/src/3709b52e6d7c7399154582e8055c0e76139a4c00/cosphere_fragment_service/word/serializers.py/#lines-33
 */
export interface BulkReadFragmentWordsResponseEntity {
    count: number;
    id?: number;
    text: string;
}
export interface BulkReadFragmentWordsResponse {
    words: BulkReadFragmentWordsResponseEntity[];
}
/**
 * https://bitbucket.org/goodai/cosphere-fragment-service/src/3709b52e6d7c7399154582e8055c0e76139a4c00/cosphere_fragment_service/word/views.py/#lines-30
 */
export interface BulkReadPublishedFragmentWordsQuery {
    first_character?: string;
    limit?: number;
    offset?: number;
}
/**
 * https://bitbucket.org/goodai/cosphere-fragment-service/src/3709b52e6d7c7399154582e8055c0e76139a4c00/cosphere_fragment_service/word/serializers.py/#lines-33
 */
export interface BulkReadPublishedFragmentWordsResponseEntity {
    count: number;
    id?: number;
    text: string;
}
export interface BulkReadPublishedFragmentWordsResponse {
    words: BulkReadPublishedFragmentWordsResponseEntity[];
}
