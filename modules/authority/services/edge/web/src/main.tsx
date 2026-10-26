// The preview stylesheet is the kit compiled alone with its default skin, for
// a page rendered where no host compiles a stylesheet around it. The edge
// stands in for the host in a run without one, so this is that page; it is
// never loaded beside a host's own stylesheet.
import "@codefly-dev/ui/preview.css";

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { readSetupData, Setup } from "./setup";
import { DATA_ISLAND, readSignInData, SignIn } from "./sign-in";

// The kit's dark mode is the `dark` class on an ancestor, as the host sets it;
// with no host to decide, the page follows the browser's preference.
const prefersDark = window.matchMedia("(prefers-color-scheme: dark)");
const paint = () =>
	document.documentElement.classList.toggle("dark", prefersDark.matches);
paint();
prefersDark.addEventListener("change", paint);

const root = document.getElementById("root");
if (!root) {
	throw new Error("the sign-in page has no root element");
}
// The edge serves one page for sign-in and for setup; the island says which.
const setup = (() => {
	try {
		return readSetupData(JSON.parse(document.getElementById(DATA_ISLAND)?.textContent || "null"));
	} catch {
		return undefined;
	}
})();
if (setup) {
	document.title = "Modules & solutions";
}
createRoot(root).render(
	<StrictMode>
		{setup ? <Setup data={setup} /> : <SignIn data={readSignInData(document)} />}
	</StrictMode>,
);
