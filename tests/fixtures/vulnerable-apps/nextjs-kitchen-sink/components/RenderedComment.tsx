// INJECT-01: dangerouslySetInnerHTML receives a non-literal (variable) value
// with no DOMPurify.sanitize anywhere in this file — a possible XSS sink.
interface RenderedCommentProps {
  rawCommentHtml: string;
}

export function RenderedComment({ rawCommentHtml }: RenderedCommentProps) {
  return <div dangerouslySetInnerHTML={{ __html: rawCommentHtml }} />;
}
