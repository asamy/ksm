# KSM needs your help to survive!

Contributions are really appreciated and can be submitted by one of the following:

- Patches (e-mail)
- Github pull requests
- git request-pull


	The github issues is a great place to start, although implementing new features
	is perfectly fine and very welcome, feel free to do whatever your little heart
	wants.

	See also (TODO / In development) seciton in this README.

The following is _not_ required, but **prefered**:

   Put your copyright on top of the file(s) you edit along with a tiny description
   with your changes.  Something like:

```c
/*
   ...
   Copyright (C) 2016, 2017 Your Name <your_email@domain.com>
	- Added support for XXX
	- Fixed bug with YYY
   ...
 */
```

   Format your git commit messages properly (A signed-off-by is good but
   **not** required, note: you can use `git commit --signoff` instead of writing
   manually.  See also Linux kernel contribution guidelines for more perks):
```
vmx: fix issue with whatever

Write as much as you would like as needed or point to some issue, although
writing is prefered, or even comments in the code itself is much better.

Optional (legal reasons, etc.):
Signed-off-by: Your Name <your_email@domain.com>
```

## Code Style

KSM uses the Linux kernel coding style, if you're unfamiliar with that, there
are multiple editor configurations that adhere to this available on the
internet, for vim you can use my configuration, here:

	https://github.com/asamy/vimfiles

To make this short, these are the rules:

- Use 8 tabs (Not spaces!)
- Preprocessor macros: leftmost column
- Labels: leftmost column
- Lines should be aligned relative to opening parenthesis, e.g.:

	```
		static void func(int a, int b,
				 int c, int d)
		{
			int a = 1 + 2 +
				4 +
				5 +
				6;
			...
		}
	```
- Case contents are not intended, but relative to the switch statement
- Opening braces for structures is on the same line (i.e. `struct my_struct {
						     };`)
- Opening braces for functions/control-blocks is on the _next_ line
- Opening braces for scopes is on the _next_ line
- Closing braces for empty or inlined structures should be on the same line as the structure definition (i.e. `struct my_struct { int i; }`)
- If-else if-else braces should be on the same line as the paranethesis, e.g.:

	```
		if (tmp) {
		} else if (other) {
		} else {
		}
	```
- Do not use braces for one-lined if/elseif/else, e.g.:

	```
		if (tmp)
			tmp();
		else if (other)
			other();
	```

## Setting up your git tree (If you're unfamiliar with Git)

For the sake of simplicity, we're going to use some names placeholders (which
									in
									reality
									you
									should
									replace
									with
									your
									own):

1. `LOCAL_BRANCH` - is your local branch you're going to be committing to (e.g.
   `my-changes`).
2. `REMOTE_BRANCH` - is the branch name you have in your remote repository (e.g.
   `pull-me`, can be the same as `LOCAL_BRANCH`).
3. `REMOTE_URL` - Your remote repository URL (e.g. https://github.com/XXX/ksm).

	Note: you do not have to have a remote repository, you can commit to
	your local copy, then just use patches, see below.
4. `USER_NAME` - Your github username

Clone the repository locally:

`git clone https://github.com/USER_NAME/ksm`

**Note**: replace USER_NAME with mine (asamy) if you're not going to use
pull-requests.

Switch to a new branch (**Optional but preferred**):

`git checkout -b LOCAL_BRANCH`

Setup remote (**Optional**: skip if you want to use the full URL each time):

`git remote add upstream https://github.com/asamy/ksm`

If there are changes in my tree that you want to get, then:

`git pull --rebase upstream master`

This will rebase my changes on top of your local tree.

	**Note**: If you skipped remote setup, then replace `upstream` with the
	URL.

	**Note**: You might want to switch to the master branch first to pull
	my changes there, then switch back to your branch, then merge them
	together later using `git merge --ff master` (`ff` is fast-forward,
						      which means it will not
						      generate a merge commit,
						      you can skip it).


If you have local changes, `--rebase` will stop and ask you to commit, you can
do this without comitting:

`git stash && git pull --rebase upstream master && git stash pop`

What this does is 1) stashes your changes, 2) pulls my changes and prepares to
rebase your stashed changes on top of mine, 3) pops the stashed changes on
top, if there any conflicts, then it will let you know and you should fix them.

Then commit your changes:

```
git add ...
git add ...
git commit --signoff -m "commit message"
```

### Submitting your changes

If you're going to use patches, then simply:

`git format-patch HEAD~X`

Where X is the number of commits to create patches from, can be ommitted to
take HEAD (i.e. most recent) commit only, e.g.:

`git format-patch HEAD~`

(You can use commit hashes instead, too.)

You can then use the patch file(s) as an attachment and e-mail them manually, or
you can use `git send-email` to do it for you.

#### Using pull requests

You have 2 options (if using 1st, then skip the rest):

1. If you're using github fork, you can just use the github pull request
   interface.
2. If you're going to use git request-pull follow.

Note: You should always push your changes before making a pull request
(regardless of the option used), like this:

	git push origin REMOTE_BRANCH

#### Using git-request-pull

(Skip this if you're using Github pull requests.)

Usage:

	git request-pull START_COMMIT REPOSITORY_URL END_COMMIT

To summarize a branch changes:

	git request-pull abcd https://github.com/USER_NAME/ksm HEAD

Which will summarize changes from commit `abcd` to `HEAD` of which you can then
e-mail me that summary.

You can also use:

	git request-pull master https://github.com/USER_NAME/ksm LOCAL_BRANCH:REMOTE_BRANCH

Which will summarize changes from the local master branch (Which should contain
							   my changes, i.e. my
							   tree) to your changes.

`REMOTE_BRANCH` can be omitted if same as `LOCAL_BRANCH`.
You can also specify a tag of your choice, in that case, use tag names instead
of commit hashes/branch names.

