// declare module 'react'
// {
//    import { HTMLAttributes, AriaAttributes, DOMAttributes, DetailedHTMLProps } from 'react';

//    interface DetiledHTMLProps<T> // extends AriaAttributes, DOMAttributes<T>
//    {
//        cut?: string;
//    }
// }

declare namespace JSX
{
    interface IntrinsicElements
    {
        // TODO
    }
}

declare module '*.mp4'
{
   const src: string;

   export default src;
}
