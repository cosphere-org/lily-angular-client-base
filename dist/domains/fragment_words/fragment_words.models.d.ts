/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
/**
 * Fragment Words Management Domain Models
 */
/**
 * https://bitbucket.org/goodai/cosphere-fragment-service/src/b023ad5da15027683028609c140260b0a1808452/cosphere_fragment_service/word/views.py/#lines-30
 */
export interface BulkReadFragmentWordsQuery {
    first_character?: string;
    limit?: number;
    offset?: number;
}
/**
 * https://bitbucket.org/goodai/cosphere-fragment-service/src/b023ad5da15027683028609c140260b0a1808452/cosphere_fragment_service/word/serializers.py/#lines-33
 */
export interface BulkReadFragmentWordsResponseEntity {
    count: number;
    id?: number;
    text: string;
}
export interface BulkReadFragmentWordsResponse {
    data: BulkReadFragmentWordsResponseEntity[];
}
/**
 * https://bitbucket.org/goodai/cosphere-fragment-service/src/b023ad5da15027683028609c140260b0a1808452/cosphere_fragment_service/word/views.py/#lines-30
 */
export interface BulkReadPublishedFragmentWordsQuery {
    first_character?: string;
    limit?: number;
    offset?: number;
}
/**
 * https://bitbucket.org/goodai/cosphere-fragment-service/src/b023ad5da15027683028609c140260b0a1808452/cosphere_fragment_service/word/serializers.py/#lines-33
 */
export interface BulkReadPublishedFragmentWordsResponseEntity {
    count: number;
    id?: number;
    text: string;
}
export interface BulkReadPublishedFragmentWordsResponse {
    data: BulkReadPublishedFragmentWordsResponseEntity[];
}
