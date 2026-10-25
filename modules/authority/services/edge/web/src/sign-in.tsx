import {
	Avatar,
	AvatarFallback,
	Badge,
	Button,
	Card,
	EmptyState,
	ErrorState,
	List,
	ListItem,
} from "@codefly-dev/ui/layout";

/** One person the authority's fixture defines, as the edge renders them. */
export interface Person {
	personId: string;
	email: string;
	organizationId: string;
	roles: string[];
	fixtureToken: string;
}

/** What the edge writes into the page: who may sign in and where to return. */
export interface SignInData {
	people: Person[];
	return: string;
}

/** The island's id, shared with the edge's template (code/signin.go). */
export const DATA_ISLAND = "sign-in";

// readSignInData reads what the edge rendered into the page. A page served any
// other way (a dev server, a stale build) has no data, which is said rather
// than shown as an empty list.
export function readSignInData(doc: Document): SignInData | Error {
	const island = doc.getElementById(DATA_ISLAND);
	if (!island?.textContent) {
		return new Error("the page carries no sign-in data: the edge did not serve it");
	}
	try {
		const parsed: unknown = JSON.parse(island.textContent);
		if (
			typeof parsed !== "object" ||
			parsed === null ||
			!Array.isArray((parsed as { people?: unknown }).people) ||
			typeof (parsed as { return?: unknown }).return !== "string"
		) {
			return new Error("the page's sign-in data has no people or no return path");
		}
		return parsed as SignInData;
	} catch (err) {
		return new Error(
			`the page's sign-in data is not JSON: ${err instanceof Error ? err.message : String(err)}`,
		);
	}
}

// initials is the mark on a person's avatar: the first letters of the words
// before the @ of their email, at most two.
function initials(email: string): string {
	const local = email.split("@")[0] ?? "";
	const letters = local
		.split(/[._+-]+/)
		.filter(Boolean)
		.map((word) => word[0]?.toUpperCase() ?? "")
		.join("");
	return letters.slice(0, 2) || "?";
}

export function SignIn({ data }: { data: SignInData | Error }) {
	return (
		<main style={{ maxWidth: 560, margin: "0 auto", padding: "48px 16px" }}>
			<Card
				title="Sign in"
				description="This run's authority signs in the people of its fixture. Choose who you are."
			>
				{data instanceof Error ? (
					<ErrorState title="Nobody can be signed in from this page" detail={data.message} />
				) : data.people.length === 0 ? (
					<EmptyState
						heading="No fixture people"
						description="This authority lists no fixture people: it signs people in through its own identity provider."
					/>
				) : (
					<List variant="divided" label="People who may sign in">
						{data.people.map((person) => (
							<ListItem
								key={person.fixtureToken}
								icon={
									<Avatar>
										<AvatarFallback>{initials(person.email)}</AvatarFallback>
									</Avatar>
								}
								description={
									<span style={{ display: "inline-flex", flexWrap: "wrap", alignItems: "center", gap: 6 }}>
										<span>{person.organizationId}</span>
										{person.roles.length === 0 ? (
											<Badge tone="neutral">no role</Badge>
										) : (
											person.roles.map((role) => (
												<Badge key={role} variant="secondary">
													{role}
												</Badge>
											))
										)}
									</span>
								}
								actions={
									// A plain form: the browser posts the choice back to the edge,
									// which signs the person in and returns them, with no script
									// between the click and the session.
									<form method="post" action="/auth/sign-in">
										<input type="hidden" name="fixtureToken" value={person.fixtureToken} />
										<input type="hidden" name="return" value={data.return} />
										<Button type="submit" size="sm">
											Sign in
										</Button>
									</form>
								}
							>
								{person.email}
							</ListItem>
						))}
					</List>
				)}
			</Card>
		</main>
	);
}
