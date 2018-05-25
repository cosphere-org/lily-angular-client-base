/**
 * Fragments Management Domain
 */
import { Injectable } from '@angular/core';
import { filter } from 'rxjs/operators';
import { Observable } from 'rxjs';
import * as _ from 'underscore';

import { ClientService, DataState } from '../../services/client.service';
import * as X from './fragments.models';

@Injectable()
export class FragmentsDomain {
    constructor(private client: ClientService) {}

    /**
     * Publish Remote Fragment
     * -------------
     *
     * Publish Remote Fragment
     */
    public publishFragment(fragmentId: any): Observable<X.PublishFragmentResponse> {
        return this.client
            .put<X.PublishFragmentResponse>(`/fragments/${fragmentId}/publish/`, {})
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * Create Remote Fragment
     * -------------
     *
     * Create Remote Fragment
     */
    public createFragment(): Observable<X.CreateFragmentResponse> {
        return this.client
            .post<X.CreateFragmentResponse>('/fragments/', {})
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
            .post<X.MergeFragmentResponse>(`/fragments/${fragmentId}/merge/`, {})
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * Update Remote Fragment
     * -------------
     *
     * Update Remote Fragment
     */
    public updateFragment(fragmentId: any, body: X.UpdateFragmentBody): Observable<X.UpdateFragmentResponse> {
        return this.client
            .put<X.UpdateFragmentResponse>(`/fragments/${fragmentId}`, body)
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * Read Fragment Sample
     * -------------
     *
     * Read Fragment Sample
     */
    public readFragmentSample(fragmentId: any): DataState<X.ReadFragmentSampleResponse> {
        return this.client.getDataState<X.ReadFragmentSampleResponse>(`/fragments/${fragmentId}/sample/`);
    }

    /**
     * Delete Remote Fragment
     * -------------
     *
     * Delete Remote Fragment
     */
    public deleteFragment(fragmentId: any): Observable<X.DeleteFragmentResponse> {
        return this.client
            .delete<X.DeleteFragmentResponse>(`/fragments/${fragmentId}`)
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * Read Remote Fragment
     * -------------
     *
     * Read Remote Fragment
     */
    public readFragment(fragmentId: any): DataState<X.ReadFragmentResponse> {
        return this.client.getDataState<X.ReadFragmentResponse>(`/fragments/${fragmentId}`);
    }

    /**
     * List Published Remote Fragments
     * -------------
     *
     * List Published Remote Fragments
     */
    public bulkReadPublishedFragments(params: X.BulkReadPublishedFragmentsQuery): DataState<X.BulkReadPublishedFragmentsResponse> {
        return this.client.getDataState<X.BulkReadPublishedFragmentsResponse>('/fragments/published/', { params });
    }

    /**
     * List Remote Fragments
     * -------------
     *
     * List Remote Fragments
     */
    public bulkReadFragments(params: X.BulkReadFragmentsQuery): DataState<X.BulkReadFragmentsResponse> {
        return this.client.getDataState<X.BulkReadFragmentsResponse>('/fragments/', { params });
    }

    /**
     * Read Fragment Diff
     * -------------
     *
     * Read Fragment Diff
     */
    public readFragmentDiff(fragmentId: any): DataState<X.ReadFragmentDiffResponse> {
        return this.client.getDataState<X.ReadFragmentDiffResponse>(`/fragments/${fragmentId}/diff/`);
    }

}