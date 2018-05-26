import {
  HttpParams,
  HttpHeaders
} from '@angular/common/http';
import { BehaviorSubject } from 'rxjs';


export interface Options {
  cache?: boolean;
  etag?: string;
  authRequired?: boolean;
  params?: HttpParams | { [param: string]: any };
  headers?: HttpHeaders | { [header: string]: string | string[] };
  reportProgress?: boolean;
}

export interface State<T> {
  [key: string]: {
    dataState: DataState<T>;
    requestState: RequestState;
  };
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
