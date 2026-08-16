import { useEffect } from 'react';

const setMetaTag = (attr, value, content) => {
  let el = document.querySelector(`meta[${attr}="${value}"]`);
  if (!el) {
    el = document.createElement('meta');
    el.setAttribute(attr, value);
    document.head.appendChild(el);
  }
  el.setAttribute('content', content);
};

const setCanonical = (href) => {
  let el = document.querySelector('link[rel="canonical"]');
  if (!el) {
    el = document.createElement('link');
    el.setAttribute('rel', 'canonical');
    document.head.appendChild(el);
  }
  el.setAttribute('href', href);
};

// Updates document.title and the description/canonical/Open Graph/Twitter meta
// tags for the current route. index.html carries the default (home page) values
// so crawlers and link-preview bots that don't execute JS still see sensible
// metadata; this hook overrides them for routes that need their own.
const useDocumentMeta = ({ title, description, path }) => {
  useEffect(() => {
    const previousTitle = document.title;
    if (title) document.title = title;
    if (description) {
      setMetaTag('name', 'description', description);
      setMetaTag('property', 'og:description', description);
      setMetaTag('name', 'twitter:description', description);
    }
    if (title) {
      setMetaTag('property', 'og:title', title);
      setMetaTag('name', 'twitter:title', title);
    }
    if (path) {
      const url = `https://fortexa.aevus.jp${path}`;
      setCanonical(url);
      setMetaTag('property', 'og:url', url);
    }

    return () => {
      document.title = previousTitle;
    };
  }, [title, description, path]);
};

export default useDocumentMeta;
