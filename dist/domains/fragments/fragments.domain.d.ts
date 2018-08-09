import { Observable } from 'rxjs';
import { ClientService } from '../../services/client.service';
import { DataState } from '../../services/client.interface';
import * as X from './fragments.models';
export declare class FragmentsDomain {
    private client;
    constructor(client: ClientService);
    /**
     * List Remote Fragments
     * -------------
     *
     * List Remote Fragments
     */
    bulkReadFragments(params: X.BulkReadFragmentsQuery): DataState<X.BulkReadFragmentsResponseEntity[]>;
    bulkReadFragments2(params: X.BulkReadFragmentsQuery): Observable<X.BulkReadFragmentsResponseEntity[]>;
    /**
     * List Published Remote Fragments
     * -------------
     *
     * List Published Remote Fragments
     */
    bulkReadPublishedFragments(params: X.BulkReadPublishedFragmentsQuery): DataState<X.BulkReadPublishedFragmentsResponseEntity[]>;
    bulkReadPublishedFragments2(params: X.BulkReadPublishedFragmentsQuery): Observable<X.BulkReadPublishedFragmentsResponseEntity[]>;
    /**
     * Create Remote Fragment
     * -------------
     *
     * Create Remote Fragment
     */
    createFragment(): Observable<X.CreateFragmentResponse>;
    /**
     * Delete Remote Fragment
     * -------------
     *
     * Delete Remote Fragment
     */
    deleteFragment(fragmentId: any): Observable<X.DeleteFragmentResponse>;
    /**
     * Merge Remote Fragment
     * -------------
     *
     * Merge Remote Fragment
     */
    mergeFragment(fragmentId: any): Observable<X.MergeFragmentResponse>;
    /**
     * Publish Remote Fragment
     * -------------
     *
     * Publish Remote Fragment
     */
    publishFragment(fragmentId: any): Observable<X.PublishFragmentResponse>;
    /**
     * Read Remote Fragment
     * -------------
     *
     * Read Remote Fragment
     */
    readFragment(fragmentId: any): DataState<X.ReadFragmentResponse>;
    readFragment2(fragmentId: any): Observable<X.ReadFragmentResponse>;
    /**
     * Read Fragment Diff
     * -------------
     *
     * Read Fragment Diff
     */
    readFragmentDiff(fragmentId: any): DataState<X.ReadFragmentDiffResponse>;
    readFragmentDiff2(fragmentId: any): Observable<X.ReadFragmentDiffResponse>;
    /**
     * Read Fragment Sample
     * -------------
     *
     * Read Fragment Sample
     */
    readFragmentSample(fragmentId: any): DataState<X.ReadFragmentSampleResponse>;
    readFragmentSample2(fragmentId: any): Observable<X.ReadFragmentSampleResponse>;
    /**
     * Update Remote Fragment
     * -------------
     *
     * Update Remote Fragment
     */
    updateFragment(fragmentId: any, body: X.UpdateFragmentBody): Observable<X.UpdateFragmentResponse>;
}
