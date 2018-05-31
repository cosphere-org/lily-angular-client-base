import {
  HttpParams,
  HttpHeaders
} from '@angular/common/http';
import { BehaviorSubject } from 'rxjs';


export interface Options {
  cache?: boolean;
  etag?: string;
  authorizationRequired?: boolean;
  params?: HttpParams | { [param: string]: any };
  headers?: HttpHeaders | { [header: string]: string | string[] };
  reportProgress?: boolean;
  responseMap?: string;
}

export interface State<T> {
  dataState: DataState<T>;
  requestState: RequestState;
}

export interface DataState<T> {
  loading$?: BehaviorSubject<boolean>;
  isData$?: BehaviorSubject<boolean>;
  data$?: BehaviorSubject<T>;
}

export interface RequestState {
  pending: boolean;
  cachedAt: number;
}
