/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
/**
 * Words Management Domain Models
 */
/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/5f215fabba7fa3925151c098fad0051162452821/cosphere_entity_service/word/views.py/#lines-31
 */
export interface BulkReadWordsQuery {
    first_character?: string;
    limit?: number;
    offset?: number;
}
/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/5f215fabba7fa3925151c098fad0051162452821/cosphere_entity_service/word/serializers.py/#lines-19
 */
export interface BulkReadWordsResponseEntity {
    text: string;
}
export interface BulkReadWordsResponse {
    words: BulkReadWordsResponseEntity[];
}
