import json
import os
import re
import subprocess

try:
    from setuptools import Command
except ImportError:
    from distutils.core import Command

REPOSITORY_API = 'https://api.github.com/repos/zachyee/presto-admin'
CURRENT_DIRECTORY = os.path.dirname(os.path.realpath(__file__))
RELEASE_LIST_DOC_PATH = os.path.join(CURRENT_DIRECTORY, 'docs/release.rst')
RELEASE_DOCS_DIRECTORY = os.path.join(CURRENT_DIRECTORY, 'docs/release/')


class release(Command):
    description = 'create source release to github and/or pypi'

    user_options = [('github', None,
                     'boolean flag indicating if a release should be created for github'),
                    ('pypi', None,
                     'boolean flag indicating if a release should be created for pypi'),
                    ('all', None,
                     'boolean flag indicating if a release should be created for github and pypi')]

    @staticmethod
    def get_latest_release():
        latest_release = subprocess.check_output(['curl', '--silent', REPOSITORY_API + '/releases/latest'])
        return json.loads(latest_release)

    @staticmethod
    def get_remote_branches():
        branches = subprocess.check_output(['curl', '--silent', REPOSITORY_API + '/branches'])
        return json.loads(branches)

    @staticmethod
    def check_branch_remote_exists(local_branch):
        for remote_branch in release.get_remote_branches():
            if local_branch == remote_branch['name']:
                print 'Local branch %s exists remotely' % local_branch
                return
        exit('Local branch %s does not exist remotely.' % local_branch)

    @staticmethod
    def check_branch_up_to_date(local_branch):
        status = subprocess.check_output(['git', 'status'])
        if 'nothing to commit, working directory clean' in status:
            print 'Local branch %s is up-to-date' % local_branch
            return
        exit('Local branch %s has a bad status.' % local_branch)

    @staticmethod
    def check_branch(local_branch):
        release.check_branch_remote_exists(local_branch)
        release.check_branch_up_to_date(local_branch)

    @staticmethod
    def get_and_check_branch():
        """
        This function gets the current local branch.
        It checks that the branch exists on the remote repo and that it is clean and up-to-date.
        """
        current_local_branch = subprocess.check_output(['git', 'symbolic-ref', '--short', 'HEAD']).strip()
        release.check_branch(current_local_branch)
        return current_local_branch

    @staticmethod
    def get_last_commit(branch):
        commit_output = subprocess.check_output(['curl', '--silent', REPOSITORY_API + '/commits/' + branch])
        return json.loads(commit_output)

    @staticmethod
    def get_and_check_target_commitish():
        branch = release.get_and_check_branch()
        return release.get_last_commit(branch)['sha']

    @staticmethod
    def get_latest_tag():
        latest_release = release.get_latest_release()
        return latest_release['tag_name']

    @staticmethod
    def is_valid_release_doc_name(release_doc_name):
        return re.match('^release-[0-9]+(\.[0-9]+){0,2}\.rst$', release_doc_name)

    @staticmethod
    def get_all_release_note_docs():
        return [content for content in os.listdir(RELEASE_DOCS_DIRECTORY)
                if (os.path.isfile(os.path.join(RELEASE_DOCS_DIRECTORY, content)) and
                    release.is_valid_release_doc_name(content))]

    @staticmethod
    def get_requested_release_tag(release_note_docs):
        """
        release_note_docs: This should be a list of all of the release document names.
            Their names should have the following format:
            release-<version_number>.rst

        This function returns the highest version number among the release document names.
        """
        release_note_names = [os.path.splitext(release_note_doc)[0] for release_note_doc in release_note_docs]
        version_numbers = [release_note_name.split('-')[1] for release_note_name in release_note_names]
        latest_version_number = sorted(version_numbers, reverse=True)[0]
        return latest_version_number

    @staticmethod
    def bump_version(version_field):
        return str(int(version_field) + 1)

    @staticmethod
    def get_acceptable_major_version_bumps(major):
        acceptable_major = release.bump_version(major)
        return [acceptable_major,
                acceptable_major + '.0',
                acceptable_major + '.0.0']

    @staticmethod
    def get_acceptable_minor_version_bumps(major, minor):
        acceptable_minor = release.bump_version(minor)
        return [major + '.' + acceptable_minor,
                major + '.' + acceptable_minor + '.0']

    @staticmethod
    def get_acceptable_patch_version_bumps(major, minor, patch):
        acceptable_patch = release.bump_version(patch)
        return [major + '.' + minor + '.' + acceptable_patch]

    @staticmethod
    def get_acceptable_version_bumps(major, minor, patch):
        """
        This functions takes as input strings major, minor, and patch which should be
        the corresponding semvar fields for a release. It returns a list of strings, which
        contains all acceptable versions. For each field bump, lower fields may be omitted
        or 0s. For instance, bumping 0.1.2's major version can result in 1, 1.0, or 1.0.0.
        """
        major_bumps = release.get_acceptable_major_version_bumps(major)
        minor_bumps = release.get_acceptable_minor_version_bumps(major, minor)
        patch_bumps = release.get_acceptable_patch_version_bumps(major, minor, patch)
        return major_bumps + minor_bumps + patch_bumps

    @staticmethod
    def get_version_field_value(version_fields, index):
        try:
            return version_fields[index]
        except IndexError:
            # The field value was omitted for the version
            return 0

    @staticmethod
    def split_tag_into_semantic_version(tag):
        version_fields = tag.split('.')
        major_version = release.get_version_field_value(version_fields, 0)
        minor_version = release.get_version_field_value(version_fields, 1)
        patch_version = release.get_version_field_value(version_fields, 2)
        return major_version, minor_version, patch_version

    @staticmethod
    def get_acceptable_tags(latest_tag):
        """
        This function takes as input the latest_tag as a string and returns
        a list of strings containing acceptable tags for the next release,
        using SemVer as the version scheme.
        """
        major, minor, patch = release.split_tag_into_semantic_version(latest_tag)
        return release.get_acceptable_version_bumps(major, minor, patch)

    @staticmethod
    def get_tag():
        release_note_docs = release.get_all_release_note_docs()
        requested_release_tag = release.get_requested_release_tag(release_note_docs)
        return requested_release_tag

    @staticmethod
    def check_tag(latest_tag, requested_release_tag):
        print 'The latest release tag is %s.\n' \
              'Detected requested release tag: %s' \
              % (latest_tag, requested_release_tag)

        acceptable_tags = release.get_acceptable_tags(latest_tag)
        if requested_release_tag not in acceptable_tags:
            exit('Detected release tag %s is not part of the acceptable release tags: %s'
                 % (requested_release_tag, acceptable_tags))

    @staticmethod
    def get_and_check_tag():
        """
        This functions finds the requested release tag by looking at the names of the
        release documents. It checks that the requested release tag is an acceptable bump
        from the latest release tag.
        """
        latest_tag = release.get_latest_tag()
        requested_release_tag = release.get_tag()
        release.check_tag(latest_tag, requested_release_tag)
        return requested_release_tag


    @staticmethod
    def check_release_file(file_path, string_contained=None, string_begins=None):
        with open(file_path, 'r') as release_file:
            file_contents = release_file.read()
            if string_contained:
                if string_contained not in file_contents:
                    exit('Expected "%s" to be in %s' % (string_contained, file_path))
            if string_begins:
                if not file_contents.startswith(string_begins):
                    print file_contents
                    exit('Expected %s to begin with "%s"' % (file_path, string_contained))

            return file_contents

    @staticmethod
    def confirm_version_changed_in_file(file_path, tag_name):
        contents = release.check_release_file(file_path)
        for line in contents.splitlines():
            if 'version' in line and '=' in line:
                if tag_name not in line:
                    exit('Version has not been updated to %s in %s' % (tag_name, file_path))

    @staticmethod
    def confirm_version_changed(tag_name):
        """
        This functions checks that the versions in setup.py and prestoadmin/__init__.py
        have been changed to match tag_name.
        """
        setup_path = os.path.join(CURRENT_DIRECTORY, 'setup.py')
        release.confirm_version_changed_in_file(setup_path, tag_name)

        init_path = os.path.join(CURRENT_DIRECTORY, 'prestoadmin/__init__.py')
        release.confirm_version_changed_in_file(init_path, tag_name)

    @staticmethod
    def confirm_release_docs_format(tag_name):
        """
        This function checks the format of the release documents.
        It checks the release document to make sure it has a header and that the
        release document name has been added to the file with the list of releases.
        """
        release_doc_name = 'release-' + tag_name + '.rst'
        release_doc_path = os.path.join(RELEASE_DOCS_DIRECTORY, release_doc_name)
        release_doc_header = 'Release ' + tag_name
        release_doc_header = ('=' * len(release_doc_header)) + '\n' + release_doc_header + '\n' + \
                             ('=' * len(release_doc_header)) + '\n'
        release_notes_file_contents = release.check_release_file(release_doc_path,
                                                                 string_begins=release_doc_header)

        string_contained = 'release/release-' + tag_name
        release_list_file_contents = release.check_release_file(RELEASE_LIST_DOC_PATH,
                                                                string_contained=string_contained)

        print 'Release docs confirmed for tag %s' % (tag_name)
        return release_notes_file_contents

    @staticmethod
    def find_nth(haystack, needle, n):
        start = haystack.find(needle)
        while start >= 0 and n > 1:
            start = haystack.find(needle, start+1)
            n -= 1
        return start

    @staticmethod
    def get_body_from_release_notes(release_notes):
        release_notes_without_header = release_notes.strip()[release.find_nth(release_notes, '\n', 3):]
        return release_notes_without_header.strip()

    @staticmethod
    def confirm_input(confirmation_prompt):
        while True:
            confirm_response = raw_input(confirmation_prompt)
            if confirm_response == 'Y':
                return True
            elif confirm_response == 'N':
                return False

    @staticmethod
    def user_confirm_body(body, tag_name):
        confirmation_prompt = '\nUsing the following for release notes:\n%s\n' \
                              'Is this okay? (Y/N) ' % body
        confirmed = release.confirm_input(confirmation_prompt)
        if confirmed:
            return
        else:
            exit('Body contents not confirmed.\n'
                 'Add/edit release contents in /docs/release/release-%s.rst'
                 % tag_name)

    @staticmethod
    def check_username(username):
        if ' ' in username:
            return False
        return True

    @staticmethod
    def user_input_username():
        while True:
            username = raw_input('Please input your Github username: ')
            if release.check_username(username):
                return username

    @staticmethod
    def make_multiline_string_json_friendly(multiline_string):
        return multiline_string.replace('\n', '\\n')

    @staticmethod
    def confirm_github_release_state_and_get_release_fields():
        """
        This functions checks that files have been added and/or modified for the release.
        It returns the fields necessary to release to Github.
        """
        target_commitish = release.get_and_check_target_commitish()
        tag_name = release.get_and_check_tag()
        release.confirm_version_changed(tag_name)
        release_notes = release.confirm_release_docs_format(tag_name)
        body = release.get_body_from_release_notes(release_notes)
        release.user_confirm_body(body, tag_name)
        body = release.make_multiline_string_json_friendly(body)
        username = release.user_input_username()
        return tag_name, target_commitish, body, username

    @staticmethod
    def build_json_post_contents(tag_name, target_commitish, name, body, draft, prerelease):
        return '{"tag_name": "%s", "target_commitish": "%s", "name": "%s", "body": "%s",' \
               ' "draft": %s, "prerelease": %s}' \
               % (tag_name, target_commitish, name, body, draft, prerelease)

    @staticmethod
    def incorrect_password(post_response):
        if 'Status: 401 Unauthorized' in post_response:
            return True
        else:
            return False

    @staticmethod
    def successful_release(post_response):
        if 'Status: 201 Created' in post_response:
            return True
        else:
            return False

    @staticmethod
    def send_release_post(post_contents, username):
        post_response = ''
        for _ in range(3):
            post_response = subprocess.check_output(['curl', '--silent', '--include',
                                                     '--data', post_contents, '-u', username,
                                                     REPOSITORY_API + '/releases'])

            if not release.incorrect_password(post_response):
                break
            print 'Incorrect password entered. Try again'

        if release.successful_release(post_response):
            print 'Successfully created release on Github'
            return True
        else:
            print post_response
            exit('Failed to create release on Github')

    @staticmethod
    def check_and_create_new_github_release():
        print '\nCreating a new github release'
        tag_name, target_commitish, body, username = release.confirm_github_release_state_and_get_release_fields()
        release_name = 'Release ' + tag_name
        is_draft = 'false'
        is_prerelease = 'false'

        json_post_contents = release.build_json_post_contents(tag_name, target_commitish, release_name,
                                                              body, is_draft, is_prerelease)
        release.send_release_post(json_post_contents, username)

    @staticmethod
    def confirm_pypi_release_state():
        """
        This functions checks that files have been added and/or modified for the release.
        It returns the fields necessary to release to Github.
        """
        release.get_and_check_target_commitish()
        tag_name = release.get_tag()
        release.confirm_version_changed(tag_name)

    @staticmethod
    def check_pypi_success(output):
        if 'Server response (200): OK' in output:
            return True
        else:
            return False

    @staticmethod
    def run_pypi_command(command):
        output = subprocess.check_output(command, stderr=subprocess.STDOUT)
        if release.check_pypi_success(output):
            return True
        else:
            print output
            return False

    @staticmethod
    def check_pypi_setup():
            command = ['python', 'setup.py', 'register', '-r', 'pypitest']
            if release.run_pypi_command(command):
                print 'Setup correctly for Pypi release'
                return
            else:
                exit('Not setup correctly for Pypi release')

    @staticmethod
    def submit_pypi_release():
        command = ['python', 'setup.py', 'sdist', 'upload', '-r', 'pypitest']
        if release.run_pypi_command(command):
            print 'Released successfully to Pypi'
            return
        else:
            exit('Failed to release to Pypi')

    @staticmethod
    def create_new_pypi_release():
        print '\nCreating a new pypi release'
        release.confirm_pypi_release_state()
        release.check_pypi_setup()
        release.submit_pypi_release()

    def initialize_options(self):
        self.github = False
        self.pypi = False
        self.all = True

    def finalize_options(self):
        if self.github or self.pypi:
            self.all = False

    def run(self):
        if self.all:
            self.check_and_create_new_github_release()
            self.create_new_pypi_release()
        if self.github:
            self.check_and_create_new_github_release()
        if self.pypi:
            self.create_new_pypi_release()

