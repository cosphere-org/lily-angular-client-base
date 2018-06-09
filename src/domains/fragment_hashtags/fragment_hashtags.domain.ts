/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */

/**
 * Fragment Hashtags Management Domain
 */
import { Injectable } from '@angular/core';
import { filter } from 'rxjs/operators';
import { Observable } from 'rxjs';
import * as _ from 'underscore';

import { ClientService } from '../../services/client.service';
import { DataState } from '../../services/client.interface';

import * as X from './fragment_hashtags.models';

@Injectable()
export class FragmentHashtagsDomain {
    constructor(private client: ClientService) {}

    /**
     * List Hashtags
     * -------------
     *
     * List Hashtags
     */
    public bulkReadFragmentHashtags(params: X.BulkReadFragmentHashtagsQuery): DataState<X.BulkReadFragmentHashtagsResponseEntity[]> {
        return this.client.getDataState<X.BulkReadFragmentHashtagsResponseEntity[]>('/fragments/hashtags/', { params, responseMap: 'data', authorizationRequired: true });
    }
    
    public bulkReadFragmentHashtags2(params: X.BulkReadFragmentHashtagsQuery): Observable<X.BulkReadFragmentHashtagsResponseEntity[]> {
        return this.client.get<X.BulkReadFragmentHashtagsResponseEntity[]>('/fragments/hashtags/', { params, responseMap: 'data', authorizationRequired: true });
    }

    /**
     * List Published Hashtags
     * -------------
     *
     * List Published Hashtags
     */
    public bulkReadPublishedFragmentHashtags(params: X.BulkReadPublishedFragmentHashtagsQuery): DataState<X.BulkReadPublishedFragmentHashtagsResponseEntity[]> {
        return this.client.getDataState<X.BulkReadPublishedFragmentHashtagsResponseEntity[]>('/fragments/hashtags/published/', { params, responseMap: 'data', authorizationRequired: false });
    }
    
    public bulkReadPublishedFragmentHashtags2(params: X.BulkReadPublishedFragmentHashtagsQuery): Observable<X.BulkReadPublishedFragmentHashtagsResponseEntity[]> {
        return this.client.get<X.BulkReadPublishedFragmentHashtagsResponseEntity[]>('/fragments/hashtags/published/', { params, responseMap: 'data', authorizationRequired: false });
    }

}