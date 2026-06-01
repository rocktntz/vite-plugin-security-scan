declare module '@babel/traverse' {
  interface NodePath<N = any> {
    node: N;
    parent: any;
    loc: {
      start: { line: number; column: number };
      end: { line: number; column: number };
    } | null;
  }

  interface TraversalOptions {
    enter?: (path: NodePath) => void;
    exit?: (path: NodePath) => void;
  }

  interface TraverseFn {
    (ast: any, options: TraversalOptions): void;
    default: TraverseFn;
  }

  const traverse: TraverseFn;
  export default traverse;
  export { NodePath };
}