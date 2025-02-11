from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, HTTPException, Depends, status
from services.db import authors_collection, posts_collection
import markdown


router = APIRouter(prefix="/authors", tags=["authors"])

class MarkdownTemplate(BaseModel):
    title: str
    author: str
    categories: List[str]
    date: datetime
    meta_description: Optional[str] = None
    meta_keywords: Optional[List[str]] = None
    content: str  # Markdown content

class BlogPost(BaseModel):
    title:str

def markdown_to_html(markdown_content: str) -> str:
    return markdown.markdown(markdown_content)

@router.post("/templates/", response_model=MarkdownTemplate)
async def create_template(template: MarkdownTemplate):
    template_dict = template.dict()
    await authors_collection.insert_one(template_dict)
    return template

@router.get("/templates/", response_model=List[MarkdownTemplate])
async def get_templates():
    templates = await authors_collection.find().to_list(100)
    return templates

@router.get("/templates/{template_id}", response_model=MarkdownTemplate)
async def get_template(template_id: str):
    template = await authors_collection.find_one({"_id": template_id})
    if template:
        return template
    raise HTTPException(status_code=404, detail="Template not found")

@router.post("/articles/from-template/{template_id}", response_model=BlogPost)
async def create_article_from_template(template_id: str, article: BlogPost):
    template = await authors_collection.find_one({"_id": template_id})
    if not template:
        raise HTTPException(status_code=404, detail="Template not found")

    # Merge template fields with article data
    article_dict = article.dict()
    article_dict.update({
        "title": template["title"],
        "author": template["author"],
        "categories": template["categories"],
        "meta_description": template["meta_description"],
        "meta_keywords": template["meta_keywords"],
        "content": markdown_to_html(template["content"]),
    })

    # Save the article
    await posts_collection.insert_one(article_dict)
    return article_dict
