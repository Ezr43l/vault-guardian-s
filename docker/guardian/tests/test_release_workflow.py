"""Regresiones estáticas de la puerta de publicación inmutable."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
RELEASE = ROOT / ".github" / "workflows" / "release.yml"


class ReleaseWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow = RELEASE.read_text(encoding="utf-8")

    def test_release_is_published_only_after_exact_draft_assets(self) -> None:
        draft = self.workflow.index(
            'gh release create "$GITHUB_REF_NAME" --draft --verify-tag'
        )
        draft_verification = self.workflow.index('verify_assets "$draft"')
        publish = self.workflow.index('-F draft=false -F prerelease=false')
        immutable = self.workflow.index('.draft == false and .immutable == true')
        published_verification = self.workflow.index('verify_assets "$published"')
        self.assertLess(draft, draft_verification)
        self.assertLess(draft_verification, publish)
        self.assertLess(publish, immutable)
        self.assertLess(immutable, published_verification)
        self.assertIn('.digest == $digest and .size == $size', self.workflow)
        self.assertIn('            "${files[@]}"', self.workflow)
        self.assertNotIn("gh release upload", self.workflow)
        self.assertIn("gh api --paginate --slurp", self.workflow)
        self.assertNotIn(
            'releases/tags/${GITHUB_REF_NAME}', self.workflow
        )
        self.assertNotIn("--clobber", self.workflow)

    def test_partial_draft_is_recovered_without_rewriting_git_or_oci_tag(self) -> None:
        self.assertIn(
            '.tag_name == $tag and .draft == true and .immutable == false',
            self.workflow,
        )
        self.assertIn(
            "steps.existing.outputs.image_exists != 'true'", self.workflow
        )
        self.assertIn(
            '.config.Labels["org.opencontainers.image.revision"] == $revision',
            self.workflow,
        )
        self.assertIn(
            "La release ${GITHUB_REF_NAME} ya está publicada; no se modifica",
            self.workflow,
        )
        delete_draft = self.workflow.index(
            '"repos/${GITHUB_REPOSITORY}/releases/${partial_id}"'
        )
        recreate_draft = self.workflow.index(
            'gh release create "$GITHUB_REF_NAME" --draft --verify-tag'
        )
        self.assertLess(delete_draft, recreate_draft)
        self.assertIn(
            '"repos/${GITHUB_REPOSITORY}/git/ref/tags/${GITHUB_REF_NAME}"',
            self.workflow,
        )
        self.assertIn(
            '"repos/${GITHUB_REPOSITORY}/git/tags/${tag_oid}"', self.workflow
        )
        self.assertIn('test "$tag_type" = "tag"', self.workflow)
        self.assertIn('test "$target_type" = "commit"', self.workflow)
        self.assertIn('test "$tag_commit_oid" = "$GITHUB_SHA"', self.workflow)
        self.assertIn('test "$current_tag_oid" = "$tag_oid"', self.workflow)
        self.assertIn(
            'test "$published_tag_commit_oid" = "$GITHUB_SHA"', self.workflow
        )
        published = self.workflow.index('published="$(gh api --method PATCH')
        final_tag_check = self.workflow.index(
            'read -r published_tag_oid published_tag_commit_oid'
        )
        self.assertLess(published, final_tag_check)
        self.assertNotIn(".target_commitish == $sha", self.workflow)
        self.assertNotIn('--target "$GITHUB_SHA"', self.workflow)
        for mutation in ("git tag ", "git push ", "docker tag ", "imagetools create"):
            self.assertNotIn(mutation, self.workflow)
        self.assertIn("type=semver,pattern={{version}}", self.workflow)
        self.assertIn("latest=false", self.workflow)
        exact_tag_gate = self.workflow.index(
            'test "$GENERATED_TAGS" = "$expected"'
        )
        publish_image = self.workflow.index("uses: docker/build-push-action@")
        self.assertLess(exact_tag_gate, publish_image)
        self.assertIn(
            'expected="${IMAGE_NAME}:${{ steps.version.outputs.value }}"',
            self.workflow,
        )
        self.assertNotIn("type=semver,pattern={{major}}.{{minor}}", self.workflow)
        self.assertNotIn("pattern={{major}}", self.workflow)
        self.assertNotIn("pattern={{minor}}", self.workflow)

    def test_immutable_releases_is_required_before_any_oci_push(self) -> None:
        immutable = self.workflow.index(
            'test "$IMMUTABLE_RELEASES_ENABLED" = "true"'
        )
        publish = self.workflow.index("uses: docker/build-push-action@")
        self.assertLess(immutable, publish)
        self.assertIn(
            "vars.IMMUTABLE_RELEASES_ENABLED", self.workflow
        )
        self.assertNotIn("IMMUTABLE_RELEASES_READ_TOKEN", self.workflow)


if __name__ == "__main__":
    unittest.main()
