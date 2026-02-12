//! Simple C expression parser and evaluator.
//!
//! Corresponds to book Ch.21 (Expression Evaluation).
//!
//! Evaluates expressions like `x + 1`, `*ptr`, `arr[2]`, `point.x`
//! in the context of the debugged program's current state.
//! Uses the variable reader for name resolution and memory access
//! for pointer dereferencing.

use crate::error::{Error, Result};

/// A parsed expression node.
#[derive(Debug, Clone)]
pub enum Expr {
    /// Integer literal.
    IntLit(i64),
    /// Variable reference by name.
    Variable(String),
    /// Unary dereference: `*expr`
    Deref(Box<Expr>),
    /// Unary address-of: `&expr`
    AddrOf(Box<Expr>),
    /// Unary negation: `-expr`
    Negate(Box<Expr>),
    /// Binary addition: `lhs + rhs`
    Add(Box<Expr>, Box<Expr>),
    /// Binary subtraction: `lhs - rhs`
    Sub(Box<Expr>, Box<Expr>),
    /// Binary multiplication: `lhs * rhs` (disambiguated from deref)
    Mul(Box<Expr>, Box<Expr>),
    /// Binary division: `lhs / rhs`
    Div(Box<Expr>, Box<Expr>),
    /// Member access: `expr.member`
    Member(Box<Expr>, String),
    /// Arrow member access: `expr->member`
    Arrow(Box<Expr>, String),
    /// Array index: `expr[index]`
    Index(Box<Expr>, Box<Expr>),
    /// Cast: `(type)expr` — stored as target byte size
    Cast(Box<Expr>, usize),
}

/// Tokenizer for expression parsing.
#[derive(Debug, Clone, PartialEq)]
enum Token {
    Int(i64),
    Ident(String),
    Plus,
    Minus,
    Star,
    Slash,
    Ampersand,
    Dot,
    Arrow,
    LBracket,
    RBracket,
    LParen,
    RParen,
    Eof,
}

struct Lexer {
    chars: Vec<char>,
    pos: usize,
}

impl Lexer {
    fn new(input: &str) -> Self {
        Lexer {
            chars: input.chars().collect(),
            pos: 0,
        }
    }

    fn peek_char(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn next_char(&mut self) -> Option<char> {
        let ch = self.chars.get(self.pos).copied();
        if ch.is_some() {
            self.pos += 1;
        }
        ch
    }

    fn skip_whitespace(&mut self) {
        while self.peek_char().map(|c| c.is_whitespace()).unwrap_or(false) {
            self.pos += 1;
        }
    }

    fn next_token(&mut self) -> Token {
        self.skip_whitespace();

        match self.peek_char() {
            None => Token::Eof,
            Some(ch) => match ch {
                '+' => {
                    self.next_char();
                    Token::Plus
                }
                '-' => {
                    self.next_char();
                    if self.peek_char() == Some('>') {
                        self.next_char();
                        Token::Arrow
                    } else {
                        Token::Minus
                    }
                }
                '*' => {
                    self.next_char();
                    Token::Star
                }
                '/' => {
                    self.next_char();
                    Token::Slash
                }
                '&' => {
                    self.next_char();
                    Token::Ampersand
                }
                '.' => {
                    self.next_char();
                    Token::Dot
                }
                '[' => {
                    self.next_char();
                    Token::LBracket
                }
                ']' => {
                    self.next_char();
                    Token::RBracket
                }
                '(' => {
                    self.next_char();
                    Token::LParen
                }
                ')' => {
                    self.next_char();
                    Token::RParen
                }
                '0'..='9' => self.lex_number(),
                'a'..='z' | 'A'..='Z' | '_' => self.lex_ident(),
                _ => {
                    self.next_char();
                    Token::Eof
                }
            },
        }
    }

    fn lex_number(&mut self) -> Token {
        let mut s = String::new();
        let mut is_hex = false;

        if self.peek_char() == Some('0') {
            s.push(self.next_char().unwrap());
            if self.peek_char() == Some('x') || self.peek_char() == Some('X') {
                s.push(self.next_char().unwrap());
                is_hex = true;
            }
        }

        while let Some(ch) = self.peek_char() {
            if is_hex && ch.is_ascii_hexdigit() {
                s.push(self.next_char().unwrap());
            } else if !is_hex && ch.is_ascii_digit() {
                s.push(self.next_char().unwrap());
            } else {
                break;
            }
        }

        let val = if is_hex {
            i64::from_str_radix(s.trim_start_matches("0x").trim_start_matches("0X"), 16)
                .unwrap_or(0)
        } else {
            s.parse().unwrap_or(0)
        };

        Token::Int(val)
    }

    fn lex_ident(&mut self) -> Token {
        let mut s = String::new();
        while let Some(ch) = self.peek_char() {
            if ch.is_alphanumeric() || ch == '_' {
                s.push(self.next_char().unwrap());
            } else {
                break;
            }
        }
        Token::Ident(s)
    }
}

/// Recursive descent parser for C-like expressions.
struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn new(input: &str) -> Self {
        let mut lexer = Lexer::new(input);
        let mut tokens = Vec::new();
        loop {
            let tok = lexer.next_token();
            let is_eof = tok == Token::Eof;
            tokens.push(tok);
            if is_eof {
                break;
            }
        }
        Parser { tokens, pos: 0 }
    }

    fn peek(&self) -> &Token {
        self.tokens.get(self.pos).unwrap_or(&Token::Eof)
    }

    fn advance(&mut self) -> Token {
        let tok = self.tokens.get(self.pos).cloned().unwrap_or(Token::Eof);
        self.pos += 1;
        tok
    }

    fn expect(&mut self, expected: &Token) -> Result<()> {
        let tok = self.advance();
        if &tok == expected {
            Ok(())
        } else {
            Err(Error::Other(format!(
                "expected {:?}, got {:?}",
                expected, tok
            )))
        }
    }

    /// Parse a full expression.
    fn parse_expr(&mut self) -> Result<Expr> {
        self.parse_additive()
    }

    /// Addition / subtraction (lowest precedence binary).
    fn parse_additive(&mut self) -> Result<Expr> {
        let mut lhs = self.parse_multiplicative()?;
        loop {
            match self.peek() {
                Token::Plus => {
                    self.advance();
                    let rhs = self.parse_multiplicative()?;
                    lhs = Expr::Add(Box::new(lhs), Box::new(rhs));
                }
                Token::Minus => {
                    self.advance();
                    let rhs = self.parse_multiplicative()?;
                    lhs = Expr::Sub(Box::new(lhs), Box::new(rhs));
                }
                _ => break,
            }
        }
        Ok(lhs)
    }

    /// Multiplication / division.
    fn parse_multiplicative(&mut self) -> Result<Expr> {
        let mut lhs = self.parse_unary()?;
        loop {
            match self.peek() {
                Token::Star => {
                    // Disambiguate: * after an expression is multiplication
                    self.advance();
                    let rhs = self.parse_unary()?;
                    lhs = Expr::Mul(Box::new(lhs), Box::new(rhs));
                }
                Token::Slash => {
                    self.advance();
                    let rhs = self.parse_unary()?;
                    lhs = Expr::Div(Box::new(lhs), Box::new(rhs));
                }
                _ => break,
            }
        }
        Ok(lhs)
    }

    /// Unary operators: *, &, -
    fn parse_unary(&mut self) -> Result<Expr> {
        match self.peek().clone() {
            Token::Star => {
                self.advance();
                let operand = self.parse_unary()?;
                Ok(Expr::Deref(Box::new(operand)))
            }
            Token::Ampersand => {
                self.advance();
                let operand = self.parse_unary()?;
                Ok(Expr::AddrOf(Box::new(operand)))
            }
            Token::Minus => {
                self.advance();
                let operand = self.parse_unary()?;
                Ok(Expr::Negate(Box::new(operand)))
            }
            _ => self.parse_postfix(),
        }
    }

    /// Postfix operators: .member, ->member, [index]
    fn parse_postfix(&mut self) -> Result<Expr> {
        let mut expr = self.parse_primary()?;
        loop {
            match self.peek().clone() {
                Token::Dot => {
                    self.advance();
                    if let Token::Ident(name) = self.advance() {
                        expr = Expr::Member(Box::new(expr), name);
                    } else {
                        return Err(Error::Other("expected member name after '.'".into()));
                    }
                }
                Token::Arrow => {
                    self.advance();
                    if let Token::Ident(name) = self.advance() {
                        expr = Expr::Arrow(Box::new(expr), name);
                    } else {
                        return Err(Error::Other("expected member name after '->'".into()));
                    }
                }
                Token::LBracket => {
                    self.advance();
                    let index = self.parse_expr()?;
                    self.expect(&Token::RBracket)?;
                    expr = Expr::Index(Box::new(expr), Box::new(index));
                }
                _ => break,
            }
        }
        Ok(expr)
    }

    /// Primary expressions: literals, variables, parenthesized.
    fn parse_primary(&mut self) -> Result<Expr> {
        match self.advance() {
            Token::Int(val) => Ok(Expr::IntLit(val)),
            Token::Ident(name) => Ok(Expr::Variable(name)),
            Token::LParen => {
                let inner = self.parse_expr()?;
                self.expect(&Token::RParen)?;
                Ok(inner)
            }
            tok => Err(Error::Other(format!("unexpected token: {:?}", tok))),
        }
    }
}

/// Parse a C-like expression string into an AST.
pub fn parse(input: &str) -> Result<Expr> {
    let mut parser = Parser::new(input);
    let expr = parser.parse_expr()?;
    if parser.peek() != &Token::Eof {
        return Err(Error::Other(format!(
            "unexpected token after expression: {:?}",
            parser.peek()
        )));
    }
    Ok(expr)
}

/// Pretty-print an expression for display.
pub fn display(expr: &Expr) -> String {
    match expr {
        Expr::IntLit(v) => format!("{}", v),
        Expr::Variable(name) => name.clone(),
        Expr::Deref(inner) => format!("*{}", display(inner)),
        Expr::AddrOf(inner) => format!("&{}", display(inner)),
        Expr::Negate(inner) => format!("-{}", display(inner)),
        Expr::Add(l, r) => format!("({} + {})", display(l), display(r)),
        Expr::Sub(l, r) => format!("({} - {})", display(l), display(r)),
        Expr::Mul(l, r) => format!("({} * {})", display(l), display(r)),
        Expr::Div(l, r) => format!("({} / {})", display(l), display(r)),
        Expr::Member(obj, member) => format!("{}.{}", display(obj), member),
        Expr::Arrow(obj, member) => format!("{}->{}", display(obj), member),
        Expr::Index(arr, idx) => format!("{}[{}]", display(arr), display(idx)),
        Expr::Cast(inner, size) => format!("({}){}", size, display(inner)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_integer_literal() {
        let expr = parse("42").unwrap();
        match expr {
            Expr::IntLit(42) => {}
            other => panic!("expected IntLit(42), got {:?}", other),
        }
    }

    #[test]
    fn parse_hex_literal() {
        let expr = parse("0x1000").unwrap();
        match expr {
            Expr::IntLit(0x1000) => {}
            other => panic!("expected IntLit(0x1000), got {:?}", other),
        }
    }

    #[test]
    fn parse_variable() {
        let expr = parse("my_var").unwrap();
        match expr {
            Expr::Variable(name) => assert_eq!(name, "my_var"),
            other => panic!("expected Variable, got {:?}", other),
        }
    }

    #[test]
    fn parse_addition() {
        let expr = parse("x + 1").unwrap();
        assert_eq!(display(&expr), "(x + 1)");
    }

    #[test]
    fn parse_deref() {
        let expr = parse("*ptr").unwrap();
        assert_eq!(display(&expr), "*ptr");
    }

    #[test]
    fn parse_addr_of() {
        let expr = parse("&x").unwrap();
        assert_eq!(display(&expr), "&x");
    }

    #[test]
    fn parse_member_access() {
        let expr = parse("point.x").unwrap();
        assert_eq!(display(&expr), "point.x");
    }

    #[test]
    fn parse_arrow_access() {
        let expr = parse("ptr->x").unwrap();
        assert_eq!(display(&expr), "ptr->x");
    }

    #[test]
    fn parse_array_index() {
        let expr = parse("arr[2]").unwrap();
        assert_eq!(display(&expr), "arr[2]");
    }

    #[test]
    fn parse_complex_expr() {
        let expr = parse("a + b * c").unwrap();
        assert_eq!(display(&expr), "(a + (b * c))");
    }

    #[test]
    fn parse_nested_deref() {
        let expr = parse("**pp").unwrap();
        assert_eq!(display(&expr), "**pp");
    }

    #[test]
    fn parse_parenthesized() {
        let expr = parse("(a + b) * c").unwrap();
        assert_eq!(display(&expr), "((a + b) * c)");
    }

    #[test]
    fn parse_negate() {
        let expr = parse("-x").unwrap();
        assert_eq!(display(&expr), "-x");
    }

    #[test]
    fn parse_chained_member() {
        let expr = parse("a.b.c").unwrap();
        assert_eq!(display(&expr), "a.b.c");
    }

    #[test]
    fn lexer_basic_tokens() {
        let mut lexer = Lexer::new("x + 42");
        assert_eq!(lexer.next_token(), Token::Ident("x".into()));
        assert_eq!(lexer.next_token(), Token::Plus);
        assert_eq!(lexer.next_token(), Token::Int(42));
        assert_eq!(lexer.next_token(), Token::Eof);
    }
}
