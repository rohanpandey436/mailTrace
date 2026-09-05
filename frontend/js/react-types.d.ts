/*
 * Ambient declarations for the React, ReactDOM and htm UMD bundles.
 *
 * There is no package manager here, so `@types/react` is not available and this
 * declares the surface the dashboard actually uses. It is deliberately narrow:
 * every hook and API used by js/ is here, and nothing else, so an unsupported
 * call is a type error rather than a silent `any`.
 */

declare namespace ReactNS {
  /** Anything React can render. */
  type Node = Element | string | number | boolean | null | undefined | Node[];

  interface Element {
    readonly type: unknown;
    readonly props: unknown;
    readonly key: string | null;
  }

  interface MutableRef<T> {
    current: T;
  }

  type Dispatch<A> = (value: A) => void;
  type SetState<S> = Dispatch<S | ((previous: S) => S)>;
  type Destructor = () => void;
  type EffectCallback = () => void | Destructor;
  type DependencyList = readonly unknown[];

  interface Static {
    createElement(type: unknown, props?: Record<string, unknown> | null, ...children: unknown[]): Element;
    Fragment: unknown;
    useState<S>(initial: S | (() => S)): [S, SetState<S>];
    useEffect(effect: EffectCallback, deps?: DependencyList): void;
    useLayoutEffect(effect: EffectCallback, deps?: DependencyList): void;
    useRef<T>(initial: T): MutableRef<T>;
    useMemo<T>(factory: () => T, deps: DependencyList): T;
    useCallback<T extends (...args: never[]) => unknown>(callback: T, deps: DependencyList): T;
    useReducer<S, A>(reducer: (state: S, action: A) => S, initial: S): [S, Dispatch<A>];
  }
}

declare namespace ReactDOMNS {
  interface Root {
    render(children: ReactNS.Node): void;
    unmount(): void;
  }
  interface Client {
    createRoot(container: globalThis.Element): Root;
  }
}

declare const ReactDOM: ReactDOMNS.Client;
