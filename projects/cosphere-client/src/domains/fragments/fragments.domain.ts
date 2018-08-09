/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */

/**
 * Fragments Management Domain
 */
import { Injectable } from '@angular/core';
import { filter } from 'rxjs/operators';
import { Observable } from 'rxjs';
import * as _ from 'underscore';

import { ClientService } from '../../services/client.service';
import { DataState } from '../../services/client.interface';

import * as X from './fragments.models';

@Injectable()
export class FragmentsDomain {
    constructor(private client: ClientService) {}

    /**
     * List Remote Fragments
     * -------------
     *
     * List Remote Fragments
     */
    public bulkReadFragments(params: X.BulkReadFragmentsQuery): DataState<X.BulkReadFragmentsResponseEntity[]> {
        return this.client.getDataState<X.BulkReadFragmentsResponseEntity[]>('/fragments/', { params, responseMap: 'fragments', authorizationRequired: true });
    }
    
    public bulkReadFragments2(params: X.BulkReadFragmentsQuery): Observable<X.BulkReadFragmentsResponseEntity[]> {
        return this.client.get<X.BulkReadFragmentsResponseEntity[]>('/fragments/', { params, responseMap: 'fragments', authorizationRequired: true });
    }

    /**
     * List Published Remote Fragments
     * -------------
     *
     * List Published Remote Fragments
     */
    public bulkReadPublishedFragments(params: X.BulkReadPublishedFragmentsQuery): DataState<X.BulkReadPublishedFragmentsResponseEntity[]> {
        return this.client.getDataState<X.BulkReadPublishedFragmentsResponseEntity[]>('/fragments/published/', { params, responseMap: 'fragments', authorizationRequired: false });
    }
    
    public bulkReadPublishedFragments2(params: X.BulkReadPublishedFragmentsQuery): Observable<X.BulkReadPublishedFragmentsResponseEntity[]> {
        return this.client.get<X.BulkReadPublishedFragmentsResponseEntity[]>('/fragments/published/', { params, responseMap: 'fragments', authorizationRequired: false });
    }

    /**
     * Create Remote Fragment
     * -------------
     *
     * Create Remote Fragment
     */
    public createFragment(): Observable<X.CreateFragmentResponse> {
        return this.client
            .post<X.CreateFragmentResponse>('/fragments/', {}, { authorizationRequired: true })
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * Delete Remote Fragment
     * -------------
     *
     * Delete Remote Fragment
     */
    public deleteFragment(fragmentId: any): Observable<X.DeleteFragmentResponse> {
        return this.client
            .delete<X.DeleteFragmentResponse>(`/fragments/${fragmentId}`, { authorizationRequired: true })
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * Merge Remote Fragment
     * -------------
     *
     * Merge Remote Fragment
     */
    public mergeFragment(fragmentId: any): Observable<X.MergeFragmentResponse> {
        return this.client
            .post<X.MergeFragmentResponse>(`/fragments/${fragmentId}/merge/`, {}, { authorizationRequired: true })
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * Publish Remote Fragment
     * -------------
     *
     * Publish Remote Fragment
     */
    public publishFragment(fragmentId: any): Observable<X.PublishFragmentResponse> {
        return this.client
            .put<X.PublishFragmentResponse>(`/fragments/${fragmentId}/publish/`, {}, { authorizationRequired: true })
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * Read Remote Fragment
     * -------------
     *
     * Read Remote Fragment
     */
    public readFragment(fragmentId: any): DataState<X.ReadFragmentResponse> {
        return this.client.getDataState<X.ReadFragmentResponse>(`/fragments/${fragmentId}`, { authorizationRequired: true });
    }
    
    public readFragment2(fragmentId: any): Observable<X.ReadFragmentResponse> {
        return this.client.get<X.ReadFragmentResponse>(`/fragments/${fragmentId}`, { authorizationRequired: true });
    }

    /**
     * Read Fragment Diff
     * -------------
     *
     * Read Fragment Diff
     */
    public readFragmentDiff(fragmentId: any): DataState<X.ReadFragmentDiffResponse> {
        return this.client.getDataState<X.ReadFragmentDiffResponse>(`/fragments/${fragmentId}/diff/`, { authorizationRequired: true });
    }
    
    public readFragmentDiff2(fragmentId: any): Observable<X.ReadFragmentDiffResponse> {
        return this.client.get<X.ReadFragmentDiffResponse>(`/fragments/${fragmentId}/diff/`, { authorizationRequired: true });
    }

    /**
     * Read Fragment Sample
     * -------------
     *
     * Read Fragment Sample
     */
    public readFragmentSample(fragmentId: any): DataState<X.ReadFragmentSampleResponse> {
        return this.client.getDataState<X.ReadFragmentSampleResponse>(`/fragments/${fragmentId}/sample/`, { authorizationRequired: false });
    }
    
    public readFragmentSample2(fragmentId: any): Observable<X.ReadFragmentSampleResponse> {
        return this.client.get<X.ReadFragmentSampleResponse>(`/fragments/${fragmentId}/sample/`, { authorizationRequired: false });
    }

    /**
     * Update Remote Fragment
     * -------------
     *
     * Update Remote Fragment
     */
    public updateFragment(fragmentId: any, body: X.UpdateFragmentBody): Observable<X.UpdateFragmentResponse> {
        return this.client
            .put<X.UpdateFragmentResponse>(`/fragments/${fragmentId}`, body, { authorizationRequired: true })
            .pipe(filter(x => !_.isEmpty(x)));
    }

}