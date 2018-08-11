/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
/**
 * Links Management Domain Models
 */
/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/5f215fabba7fa3925151c098fad0051162452821/.venv/src/lily/lily/base/serializers.py/#lines-158
 */
export interface DeleteLinkResponse {
}
/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/5f215fabba7fa3925151c098fad0051162452821/cosphere_entity_service/grid/views.py/#lines-48
 */
export interface ReadOrCreateLinkBody {
    from_card_id: number;
    to_card_id: number;
}
/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/5f215fabba7fa3925151c098fad0051162452821/cosphere_entity_service/grid/serializers.py/#lines-8
 */
export declare enum ReadOrCreateLinkResponseKind {
    CARD = "CARD",
    FRAGMENT = "FRAGMENT",
    HASHTAG = "HASHTAG",
    PATH = "PATH",
    TERM = "TERM",
}
export interface ReadOrCreateLinkResponse {
    author_id?: any;
    created_timestamp: number;
    from_card_id?: any;
    id?: number;
    kind: ReadOrCreateLinkResponseKind;
    reference_id: number;
    to_card_id?: any;
    value: number;
}
