/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */

/**
 * Tasks Management Domain Models
 */

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/5f215fabba7fa3925151c098fad0051162452821/cosphere_entity_service/task/views.py/#lines-33
 */

export enum BulkReadTasksQueryQueueType {
    DN = 'DN',
    HP = 'HP',
    OT = 'OT',
    PR = 'PR',
}

export interface BulkReadTasksQuery {
    ascending?: boolean;
    limit?: number;
    offset?: number;
    queue_type?: BulkReadTasksQueryQueueType;
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/5f215fabba7fa3925151c098fad0051162452821/cosphere_entity_service/task/serializers.py/#lines-55
 */

export enum BulkReadTasksResponseQueueType {
    DN = 'DN',
    HP = 'HP',
    OT = 'OT',
    PR = 'PR',
}

export interface BulkReadTasksResponseEntity {
    archived?: boolean;
    content?: Object;
    created_timestamp: number;
    done_date: string;
    done_timestamp: number;
    id?: number;
    order_number?: number;
    queue_type?: BulkReadTasksResponseQueueType;
    total_time?: number;
}

export interface BulkReadTasksResponse {
    tasks: BulkReadTasksResponseEntity[];
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/5f215fabba7fa3925151c098fad0051162452821/cosphere_entity_service/task/views.py/#lines-33
 */

export enum BulkReadTaskBinsQueryQueueType {
    DN = 'DN',
    HP = 'HP',
    OT = 'OT',
    PR = 'PR',
}

export interface BulkReadTaskBinsQuery {
    ascending?: boolean;
    limit?: number;
    offset?: number;
    queue_type?: BulkReadTaskBinsQueryQueueType;
}

/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/5f215fabba7fa3925151c098fad0051162452821/cosphere_entity_service/task/serializers.py/#lines-71
 */

export enum BulkReadTaskBinsResponseQueueType {
    DN = 'DN',
    HP = 'HP',
    OT = 'OT',
    PR = 'PR',
}

export interface BulkReadTaskBinsResponseEntity {
    done_date: string;
    tasks: {
        archived?: boolean;
        content?: Object;
        created_timestamp: number;
        done_date: string;
        done_timestamp: number;
        id?: number;
        order_number?: number;
        queue_type?: BulkReadTaskBinsResponseQueueType;
        total_time?: number;
    }[];
}

export interface BulkReadTaskBinsResponse {
    tasks_bins: BulkReadTaskBinsResponseEntity[];
}