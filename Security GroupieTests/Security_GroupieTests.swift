//
//  Security_GroupieTests.swift
//  Security GroupieTests
//
//  Created by Chris Morrell on 12/11/25.
//

import Testing
@testable import Security_Groupie

struct INIParserTests {

    @Test func parsesBasicSection() {
        let content = """
        [default]
        key = value
        """
        let parser = INIParser(content: content)

        #expect(parser.sectionNames.contains("default"))
        #expect(parser.value(forKey: "key", inSection: "default") == "value")
    }

    @Test func parsesMultipleSections() {
        let content = """
        [section1]
        foo = bar

        [section2]
        baz = qux
        """
        let parser = INIParser(content: content)

        #expect(parser.sectionNames.count == 2)
        #expect(parser.value(forKey: "foo", inSection: "section1") == "bar")
        #expect(parser.value(forKey: "baz", inSection: "section2") == "qux")
    }

    @Test func handlesWhitespaceAroundEquals() {
        let content = """
        [default]
        key=value
        spaced = spaced_value
        extra_spaced   =   extra_value
        """
        let parser = INIParser(content: content)

        #expect(parser.value(forKey: "key", inSection: "default") == "value")
        #expect(parser.value(forKey: "spaced", inSection: "default") == "spaced_value")
        #expect(parser.value(forKey: "extra_spaced", inSection: "default") == "extra_value")
    }

    @Test func isCaseInsensitiveForKeys() {
        let content = """
        [default]
        AWS_ACCESS_KEY_ID = AKIAIOSFODNN7EXAMPLE
        aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
        """
        let parser = INIParser(content: content)

        #expect(parser.value(forKey: "aws_access_key_id", inSection: "default") == "AKIAIOSFODNN7EXAMPLE")
        #expect(parser.value(forKey: "AWS_ACCESS_KEY_ID", inSection: "default") == "AKIAIOSFODNN7EXAMPLE")
        #expect(parser.value(forKey: "AWS_SECRET_ACCESS_KEY", inSection: "default") == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
    }

    @Test func ignoresComments() {
        let content = """
        # This is a comment
        [default]
        ; This is also a comment
        key = value
        # Another comment
        """
        let parser = INIParser(content: content)

        #expect(parser.sectionNames == ["default"])
        #expect(parser.value(forKey: "key", inSection: "default") == "value")
    }

    @Test func ignoresEmptyLines() {
        let content = """
        [default]

        key = value

        another = thing

        """
        let parser = INIParser(content: content)

        #expect(parser.value(forKey: "key", inSection: "default") == "value")
        #expect(parser.value(forKey: "another", inSection: "default") == "thing")
    }

    @Test func handlesEmptyContent() {
        let parser = INIParser(content: "")

        #expect(parser.sectionNames.isEmpty)
    }

    @Test func handlesContentWithNoSections() {
        let content = """
        key = value
        another = thing
        """
        let parser = INIParser(content: content)

        // Keys without a section header should be ignored
        #expect(parser.sectionNames.isEmpty)
    }

    @Test func parsesAWSCredentialsFormat() {
        let content = """
        [default]
        aws_access_key_id = AKIAIOSFODNN7EXAMPLE
        aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

        [production]
        aws_access_key_id = AKIAI44QH8DHBEXAMPLE
        aws_secret_access_key = je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY
        region = us-west-2
        """
        let parser = INIParser(content: content)

        #expect(parser.sectionNames.count == 2)
        #expect(parser.value(forKey: "aws_access_key_id", inSection: "default") == "AKIAIOSFODNN7EXAMPLE")
        #expect(parser.value(forKey: "aws_access_key_id", inSection: "production") == "AKIAI44QH8DHBEXAMPLE")
        #expect(parser.value(forKey: "region", inSection: "production") == "us-west-2")
        #expect(parser.value(forKey: "region", inSection: "default") == nil)
    }

    @Test func parsesAWSConfigFormat() {
        let content = """
        [default]
        region = us-east-1
        output = json

        [profile production]
        region = us-west-2
        output = text
        """
        let parser = INIParser(content: content)

        #expect(parser.sectionNames.contains("default"))
        #expect(parser.sectionNames.contains("profile production"))
        #expect(parser.value(forKey: "region", inSection: "default") == "us-east-1")
        #expect(parser.value(forKey: "region", inSection: "profile production") == "us-west-2")
    }

    @Test func handlesValuesWithEqualsSign() {
        let content = """
        [default]
        key = value=with=equals
        """
        let parser = INIParser(content: content)

        #expect(parser.value(forKey: "key", inSection: "default") == "value=with=equals")
    }

    @Test func handlesLeadingAndTrailingWhitespaceInSections() {
        let content = """
        [  spaced  ]
        key = value
        """
        let parser = INIParser(content: content)

        // Section names preserve their content (including internal spaces)
        #expect(parser.sectionNames.contains("  spaced  "))
    }

    @Test func keysMethodReturnsAllKeys() {
        let content = """
        [default]
        key1 = value1
        key2 = value2
        key3 = value3
        """
        let parser = INIParser(content: content)

        let keys = parser.keys(inSection: "default")
        #expect(keys.count == 3)
        #expect(keys.contains("key1"))
        #expect(keys.contains("key2"))
        #expect(keys.contains("key3"))
    }

    @Test func returnsNilForMissingSection() {
        let content = """
        [default]
        key = value
        """
        let parser = INIParser(content: content)

        #expect(parser.value(forKey: "key", inSection: "nonexistent") == nil)
    }

    @Test func returnsNilForMissingKey() {
        let content = """
        [default]
        key = value
        """
        let parser = INIParser(content: content)

        #expect(parser.value(forKey: "missing", inSection: "default") == nil)
    }

    @Test func ignoresLinesWithoutValues() {
        let content = """
        [default]
        key =
        = value
        noequals
        valid = data
        """
        let parser = INIParser(content: content)

        #expect(parser.value(forKey: "key", inSection: "default") == nil)
        #expect(parser.value(forKey: "", inSection: "default") == nil)
        #expect(parser.value(forKey: "valid", inSection: "default") == "data")
    }
}
