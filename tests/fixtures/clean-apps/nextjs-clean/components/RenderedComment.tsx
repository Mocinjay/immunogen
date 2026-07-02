// INJECT-01 must NOT fire: the HTML is sanitized via DOMPurify.sanitize
// before being passed to dangerouslySetInnerHTML.
import DOMPurify from "dompurify";

interface RenderedCommentProps {
  rawCommentHtml: string;
}

export function RenderedComment({ rawCommentHtml }: RenderedCommentProps) {
  const safeHtml = DOMPurify.sanitize(rawCommentHtml);
  return <div dangerouslySetInnerHTML={{ __html: safeHtml }} />;
}
